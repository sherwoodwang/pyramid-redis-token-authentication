import pickle
import redis
from zope.interface import implementer, Interface
from pyramid.interfaces import IAuthenticationPolicy, PHASE2_CONFIG
from pyramid.security import Everyone, Authenticated
from webob.cookies import CookieProfile
from random import randint
import hashlib
import hmac
import base64
import binascii
from urllib.parse import quote as urlquote, unquote as urlunquote
import os
import sys
import importlib
import re


basic_characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.'


def token_generator(length):
    return ''.join([basic_characters[randint(0, len(basic_characters) - 1)] for i in range(length)])


class _AuthRecord:
    def __init__(self, session, key):
        self._session = session
        self._key = key
        self._storage = session[key]

    def set(self, name, value):
        if value is None:
            if name in self._storage:
                del self._storage[name]
        else:
            self._storage[name] = value
            self._session.changed()

    def get(self, name, default=None):
        if name in self._storage:
            return self._storage[name]
        else:
            return default

    @property
    def user_id(self):
        return self.get('user_id')

    @user_id.setter
    def user_id(self, value):
        self.set('user_id', value)

    @property
    def token(self):
        return self.get('token')

    @token.setter
    def token(self, value):
        self.set('token', value)


class _Counterfoil:
    def __init__(self, user_id, timeout):
        self.user_id = user_id
        self.timeout = timeout
        self.last_user_agent = None
        self.last_address = None


class AuthenticationError(Exception):
    pass


class ITokenManager(Interface):
    def revoke_token(self, token):
        pass

    def check_token(self, userid, token):
        pass

    def generate_access_key(self, userid, token):
        pass

    def parse_principals(self, principals):
        pass


class InvalidArgumentError(BaseException):
    pass


class _LiteralValueSerializer:
    @staticmethod
    def dumps(value):
        return urlquote(value).encode('ascii')

    @staticmethod
    def loads(value):
        return urlunquote(value.decode('ascii'))


@implementer(IAuthenticationPolicy, ITokenManager)
class RedisTokenAuthenticationPolicy:
    """A token-based authentication policy which maintains token table in Redis

    User id and tokens are stored in session. Tokens are validated against counterfoils in Redis. When a counterfoil is
    revoked, the associated token becomes invalid.

    An unauthenticated_userid is the user id stored in session.

    When there is a valid token, the user id is an authenticated_userid.

    The visitor would get following principals: Authenticated, "token:[token id]", "user:[user id]"."""

    def __init__(self,
                 redis_url=None,
                 token_length=16,  # the length of access key would be 48 chars longer than token
                 trusted_host=True,
                 authentication_secret=None,
                 from_session_property='auth',
                 from_header='X-Access-Key',
                 to_header='X-Set-Access-Key',
                 from_parameter='access_key',
                 from_cookie='access_key',
                 counterfoil_checker=None,
                 callback=None):
        if redis_url is None:
            raise InvalidArgumentError

        self._token_length = token_length
        self._trusted_host = trusted_host

        if authentication_secret is None:
            authentication_secret = os.urandom(64)
        if isinstance(authentication_secret, str):
            self._authentication_secret = hashlib.sha512(authentication_secret.encode()).digest()
        else:
            self._authentication_secret = authentication_secret

        self._from_session_property = from_session_property
        self._from_header = from_header
        self._to_header = to_header
        self._from_parameter = from_parameter
        self._from_cookie = from_cookie
        if self._from_cookie is not None:
            if isinstance(self._from_cookie, CookieProfile):
                self._cookie_profile = self._from_cookie
            else:
                self._cookie_profile = CookieProfile(self._from_cookie, serializer=_LiteralValueSerializer)
        self._connection_pool = redis.ConnectionPool.from_url(redis_url)
        self._counterfoil_checker = counterfoil_checker \
            if counterfoil_checker is not None else \
            lambda request, last_address, last_user_agent: True
        self._callback = callback \
            if callback is not None else \
            lambda userid, request: []

    @staticmethod
    def from_settings(settings):
        defkwargs = {}

        argnames = [
            'redis_url',
            'token_length',
            'trusted_host',
            'authentication_secret',
            'from_session_property',
            'from_parameter',
            'from_header',
            'to_header',
            'from_cookie',
            'callback',
        ]

        prefix = 'token_authentication.'
        for name in settings:
            if name.startswith(prefix):
                argname = name[len(prefix):]
                if argname in argnames:
                    defkwargs[argname] = settings[name]
                else:
                    print('Unknown configuration key: {}'.format(name), file=sys.stderr)

        if 'from_session_property' in defkwargs and defkwargs['from_session_property'] == '':
            defkwargs['from_session_property'] = None

        if 'from_cookie' in defkwargs and defkwargs['from_cookie'] == '':
            defkwargs['from_cookie'] = None

        if 'token_length' in defkwargs and not isinstance(defkwargs['token_length'], int):
            defkwargs['token_length'] = int(defkwargs['token_length'])

        if 'callback' in defkwargs and isinstance(defkwargs['callback'], str):
            callback_format = re.compile('(?P<package>[a-zA-Z_.]+):(?P<function>[a-zA-Z_.]+)')
            m = callback_format.match(defkwargs['callback'])
            if m:
                defkwargs['callback'] = getattr(importlib.import_module(m.group('package')), m.group('function'))

        def factory(**kwargs):
            realkwargs = defkwargs.copy()
            realkwargs.update(kwargs)
            return RedisTokenAuthenticationPolicy(**realkwargs)

        return factory

    def _get_redis(self):
        return redis.StrictRedis(connection_pool=self._connection_pool)

    def _get_auth_record_from_session(self, request, create=False):
        if self._from_session_property is None:
            return None

        if self._trusted_host is not True and request.host not in self._trusted_host:
            return None

        if create and self._from_session_property not in request.session:
            request.session[self._from_session_property] = {}

        if self._from_session_property in request.session:
            return _AuthRecord(request.session, self._from_session_property)
        else:
            return None

    def _clean_auth_record_from_session(self, request):
        if self._from_session_property is None:
            return

        del request.session[self._from_session_property]

    def _get_token_from_session(self, request):
        info = self._get_auth_record_from_session(request, False)

        if info is None:
            return None, None

        def user_id_checker(user_id):
            return user_id == info.user_id

        return info.token, user_id_checker

    def _get_token_from_access_key(self, request):
        if self._authentication_secret is None:
            return None, None

        access_key = None

        if access_key is None:
            if self._from_header is not None:
                access_key = request.headers.get(self._from_header, None)

        if access_key is None:
            if self._from_parameter is not None:
                access_key = request.params.get(self._from_parameter, None)

        if access_key is None:
            if self._from_cookie is not None:
                if self._trusted_host is True or request.host in self._trusted_host:
                    access_key = self._cookie_profile(request).get_value()

        if access_key is None:
            return None, None

        token = access_key[:self._token_length]

        try:
            authentication_data = access_key[self._token_length:].encode('ascii')
        except UnicodeEncodeError:
            return None, None

        try:
            authentication_data = base64.b64decode(authentication_data, b'_.')
        except binascii.Error:
            return None, None

        user_id_hash = authentication_data[:4]

        provided_hmac = authentication_data[4:]
        expected_hmac = hmac.new(
            self._authentication_secret,
            digestmod=hashlib.sha256,
            msg=token.encode() + user_id_hash).digest()

        if not hmac.compare_digest(expected_hmac, provided_hmac):
            return None, None

        def user_id_checker(user_id):
            return user_id_hash == self._generate_user_id_hash(user_id)

        return token, user_id_checker

    def generate_access_key(self, user_id, token):
        user_id_hash = self._generate_user_id_hash(user_id)

        if self._authentication_secret is None:
            return None

        return token + base64.b64encode(user_id_hash + hmac.new(
            self._authentication_secret,
            digestmod=hashlib.sha256,
            msg=token.encode() + user_id_hash).digest(), b'_.').decode('ascii')

    @staticmethod
    def _generate_user_id_hash(user_id):
        if not isinstance(user_id, str):
            user_id = str(user_id)

        return hashlib.sha224(user_id.encode()).digest()[-4:]

    def authenticated_userid(self, request):
        for principal in request.effective_principals:
            if principal.startswith('user:'):
                return principal[len('user:'):]

        return None

    def unauthenticated_userid(self, request):
        info = self._get_auth_record_from_session(request)

        if info is None:
            return None

        # there is a authentication record in session
        return info.user_id

    def effective_principals(self, request):
        principals = [Everyone]

        token = None
        user_id_checker = None

        if token is None:
            token, user_id_checker = self._get_token_from_access_key(request)

        if token is None:
            token, user_id_checker = self._get_token_from_session(request)

        if token is None or user_id_checker is None:
            return principals  # common principals

        # there is a authentication record in session
        redis_server = self._get_redis()
        counterfoil = redis_server.get(token)

        if counterfoil is None:
            return principals  # common principals

        # there is a counterfoil in Redis for user's token
        try:
            counterfoil = pickle.loads(counterfoil)  # type: _Counterfoil
        except pickle.UnpicklingError:
            self.forget(request)
            return principals

        if not user_id_checker(counterfoil.user_id):
            self.forget(request)
            return principals

        if not self._counterfoil_checker(request, counterfoil.last_address, counterfoil.last_user_agent):
            self.forget(request)
            return principals

        # the counterfoil belongs to the user
        principals.append(Authenticated)
        principals.append('user:{}'.format(counterfoil.user_id))
        principals.append('token:{}'.format(token))
        principals += self._callback(counterfoil.user_id, request)

        updated = False

        if counterfoil.last_user_agent != request.user_agent:
            counterfoil.last_user_agent = request.user_agent
            updated = True

        if counterfoil.last_address != request.client_addr:
            counterfoil.last_address = request.client_addr
            updated = True

        # extend lifetime of counterfoil
        if updated:
            redis_server.set(token, pickle.dumps(counterfoil), ex=counterfoil.timeout)
        else:
            redis_server.expire(token, counterfoil.timeout)

        # update session
        info = self._get_auth_record_from_session(request, create=True)
        if info is not None:
            info.token = token
            info.user_id = counterfoil.user_id

        return principals

    def remember(self,
                 request,
                 userid,
                 timeout=None,
                 long_lifetime_cookie=False,
                 the_token_generator=token_generator,
                 callback=None):
        if timeout is None:
            timeout = 7 * 24 * 60 * 60

        redis_server = self._get_redis()

        user_id = str(userid)

        token = None

        def user_id_checker(user_id):
            return False

        if token is None:
            token, user_id_checker = self._get_token_from_access_key(request)

        if token is None:
            token, user_id_checker = self._get_token_from_session(request)

        class NoValidToken(BaseException):
            pass

        try:
            if token is None:
                raise NoValidToken

            if not user_id_checker(user_id):
                raise NoValidToken

            counterfoil = redis_server.get(token)
            if counterfoil is None:
                raise NoValidToken

            try:
                counterfoil = pickle.loads(counterfoil)  # type: _Counterfoil
            except pickle.UnpicklingError:
                raise NoValidToken

            if counterfoil.user_id != user_id:
                raise NoValidToken

            # update lifetime of counterfoil
            counterfoil.timeout = timeout
            redis_server.set(token, pickle.dumps(counterfoil), ex=counterfoil.timeout)
        except NoValidToken:
            counterfoil = _Counterfoil(user_id, timeout)

            ret = None
            token = None
            while ret is None:
                token = the_token_generator(self._token_length)
                ret = redis_server.set(token, pickle.dumps(counterfoil), ex=counterfoil.timeout, nx=True)

        if callback is not None:
            callback(token)

        info = self._get_auth_record_from_session(request, create=True)  # type: _AuthRecord

        if info is not None:
            info.user_id = user_id
            info.token = token

        access_key = self.generate_access_key(user_id, token)

        if access_key is not None:
            headers = []

            if self._to_header is not None:
                headers.append((self._to_header, access_key))

            if self._from_cookie is not None:
                if self._trusted_host is True or request.host in self._trusted_host:
                    cookie_settings = {}

                    if long_lifetime_cookie:
                        cookie_settings['max_age'] = timeout

                    headers += self._cookie_profile(request).get_headers(access_key, **cookie_settings)
            return headers
        else:
            return []

    def forget(self, request):
        token, _ = self._get_token_from_access_key(request)

        if token is not None:
            self.revoke_token(token)

        token, _ = self._get_token_from_session(request)
        if token is not None:
            self.revoke_token(token)
        self._clean_auth_record_from_session(request)

        headers = []

        if self._to_header is not None:
            headers.append((self._to_header, ''))

        if self._from_cookie is not None:
            if self._trusted_host is True or request.host in self._trusted_host:
                headers += self._cookie_profile(request).get_headers(None)
        return headers

    def revoke_token(self, token):
        if token is None:
            return

        redis_server = self._get_redis()
        redis_server.delete(token)

    def validate_token(self, userid, token):
        redis_server = self._get_redis()
        counterfoil = redis_server.get(token)
        if counterfoil is None:
            return False

        counterfoil = pickle.loads(counterfoil)  # type: _Counterfoil
        if counterfoil.user_id != userid:
            return False

        return True

    def parse_principals(self, principals):
        user_id = None
        token = None

        for principal in principals:
            if principal.startswith('user:'):
                user_id = principal[5:]
            elif principal.startswith('token:'):
                token = principal[6:]

        return user_id, token


def get_token_manager(request) -> RedisTokenAuthenticationPolicy:
    return request.registry.getUtility(ITokenManager)


def includeme(config):
    def register_token_manager():
        authentication_policy = config.registry.queryUtility(IAuthenticationPolicy)

        if ITokenManager.providedBy(authentication_policy):
            config.registry.registerUtility(authentication_policy, ITokenManager)

    config.action('register_token_manager', register_token_manager, order=(PHASE2_CONFIG + 1))
