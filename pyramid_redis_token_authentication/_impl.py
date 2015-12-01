import pickle
import redis
from zope.interface import implementer, Interface
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from random import randint
import hashlib
import hmac
import base64
import binascii


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


@implementer(IAuthenticationPolicy, ITokenManager)
class RedisTokenAuthenticationPolicy:
    """A token-based authentication policy which maintains token table in Redis

    User id and tokens are stored in session. Tokens are validated against counterfoils in Redis. When a counterfoil is
    revoked, the associated token becomes invalid.

    An unauthenticated_userid is the user id stored in session.

    When there is a valid token, the user id is an authenticated_userid.

    The visitor would get following principals: Authenticated, "token:[token id]", "user:[user id]"."""

    def __init__(self,
                 redisurl,
                 token_length=16,  # the length of access key would be 48 chars longer than token
                 session_key='auth',
                 session_host=True,
                 key_authentication_secret=None,
                 key_parameter='access_key',
                 key_header='X-Access-Key',
                 key_header_for_setting='X-Set-Access-Key',
                 counterfoil_checker=None,
                 callback=None):
        self._token_length = token_length
        self._session_key = session_key
        self._session_host = session_host
        if isinstance(key_authentication_secret, str):
            self._key_authentication_secret = hashlib.sha512(key_authentication_secret.encode()).digest()
        else:
            self._key_authentication_secret = key_authentication_secret
        self._key_parameter = key_parameter
        self._key_header = key_header
        self._key_header_for_setting = key_header_for_setting
        self._connection_pool = redis.ConnectionPool.from_url(redisurl)
        self._counterfoil_checker = counterfoil_checker \
            if counterfoil_checker is not None else \
            lambda request, last_address, last_user_agent: True
        self._callback = callback \
            if callback is not None else \
            lambda userid, request: []

    def _get_redis(self):
        return redis.Redis(connection_pool=self._connection_pool)

    def _get_auth_record_from_session(self, request, create=False):
        if self._session_host is not True and request.host not in self._session_host:
            return None

        if create and self._session_key not in request.session:
            request.session[self._session_key] = {}

        if self._session_key in request.session:
            return _AuthRecord(request.session, self._session_key)
        else:
            return None

    def _clean_auth_record_from_session(self, request):
        del request.session[self._session_key]

    def _get_token_from_session(self, request):
        info = self._get_auth_record_from_session(request, False)

        if info is None:
            return None, None

        def user_id_checker(user_id):
            return user_id == info.user_id

        return info.token, user_id_checker

    def _get_token_from_access_key(self, request):
        if self._key_authentication_secret is None:
            return None, None

        access_key = None

        if access_key is None:
            if self._key_header is not None:
                access_key = request.headers.get(self._key_header, None)

        if access_key is None:
            if self._key_parameter is not None:
                access_key = request.params.get(self._key_parameter, None)

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
            self._key_authentication_secret,
            digestmod=hashlib.sha256,
            msg=token.encode() + user_id_hash).digest()

        if not hmac.compare_digest(expected_hmac, provided_hmac):
            return None, None

        def user_id_checker(user_id):
            return user_id_hash == self._generate_user_id_hash(user_id)

        return token, user_id_checker

    def generate_access_key(self, user_id, token):
        user_id_hash = self._generate_user_id_hash(user_id)

        if self._key_authentication_secret is None:
            return None

        return token + base64.b64encode(user_id_hash + hmac.new(
            self._key_authentication_secret,
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
        principals += [additional_principal
                       for principal in principals
                       for additional_principal in self._callback(principal, request)]

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

        return principals

    def remember(self,
                 request,
                 userid,
                 timeout=None,
                 the_token_generator=token_generator,
                 callback=None):
        if timeout is None:
            timeout = 7 * 24 * 60 * 60

        redis_server = self._get_redis()

        user_id = str(userid)

        info = self._get_auth_record_from_session(request, create=True)  # type: _AuthRecord

        class NoValidToken(BaseException):
            pass

        try:
            if info.user_id != user_id:
                raise NoValidToken

            counterfoil = redis_server.get(info.token)
            if counterfoil is None:
                raise NoValidToken

            try:
                counterfoil = pickle.loads(counterfoil)  # type: _Counterfoil
            except pickle.UnpicklingError:
                raise NoValidToken

            if counterfoil.user_id != info.user_id:
                raise NoValidToken

            # update lifetime of counterfoil
            counterfoil.timeout = timeout
            redis_server.set(info.token, pickle.dumps(counterfoil), ex=counterfoil.timeout)
            token = info.token

        except NoValidToken:
            if info.token is not None:
                redis_server.delete(info.token)

            counterfoil = _Counterfoil(user_id, timeout)

            ret = None
            token = None
            while ret is None:
                token = the_token_generator(self._token_length)
                ret = redis_server.set(token, pickle.dumps(counterfoil), ex=counterfoil.timeout, nx=True)
            info.token = token

        info.user_id = user_id

        callback(token)

        access_key = self.generate_access_key(user_id, token)

        if access_key is not None:
            return [(self._key_header_for_setting, access_key)]
        else:
            return []

    def forget(self, request):
        info = self._get_auth_record_from_session(request)
        if info is not None:
            self.revoke_token(info.token)
            self._clean_auth_record_from_session(request)
        return [(self._key_header_for_setting, '')]

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
    kwargs = {}
    settings = config.get_settings()

    argnames = [
        'token_length',
        'session_key',
        'session_host',
        'key_authentication_secret',
        'key_parameter',
        'key_header',
        'key_header_for_setting',
        'counterfoil_checker',
        'callback',
    ]

    for argname in argnames:
        settingname = 'token_authentication.' + argname
        if settingname in settings:
            kwargs[argname] = settings[settingname]

    if 'token_length' in kwargs and not isinstance(kwargs['token_length'], int):
        kwargs['token_length'] = int(kwargs['token_length'])

    authentication_policy = RedisTokenAuthenticationPolicy(
        config.get_settings()['token_authentication.url'],
        **kwargs)

    config.set_authentication_policy(authentication_policy)

    def register_token_manager():
        config.registry.registerUtility(authentication_policy, ITokenManager)

    config.action('register_token_manager', register_token_manager)
