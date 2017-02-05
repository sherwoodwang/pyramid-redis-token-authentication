import pickle
import redis
from zope.interface import implementer, Interface
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from webob.cookies import CookieProfile
import hashlib
import hmac
import base64
import binascii
from urllib.parse import quote as urlquote, unquote as urlunquote
import os
import sys
import importlib
import re
from Crypto.Cipher import AES
from Crypto import Random
from collections import namedtuple
from weakref import finalize


AccessKey = namedtuple('AccessKey', ['user_id', 'token'])


class AccessKeyAlgorithm:
    def __init__(self, secret, token_length):
        self.secret = secret
        self.token_length = token_length

        self.encryption_key = hmac.new(
            secret,
            digestmod=hashlib.sha256,
            msg='Encryption Key'.encode('ascii')).digest()
        self.authentication_key = hmac.new(
            secret,
            digestmod=hashlib.sha256,
            msg='Authentication Key'.encode('ascii')).digest()

    def load(self, data):
        if not isinstance(data, str):
            raise InvalidArgumentError

        try:
            data = base64.b64decode(data.encode('ascii'), b'_.')
        except binascii.Error:
            return None

        provided_hmac = data[:32]
        data = data[32:]

        expected_hmac = hmac.new(
            self.authentication_key,
            digestmod=hashlib.sha256,
            msg=data).digest()

        if not hmac.compare_digest(provided_hmac, expected_hmac):
            return None

        iv = data[:AES.block_size]
        data = data[AES.block_size:]

        cipher = AES.new(self.encryption_key, AES.MODE_CFB, iv)
        data = cipher.decrypt(data)

        if len(data) < self.token_length + 1:
            return None

        token = data[:self.token_length]

        try:
            user_id = data[self.token_length:].decode('utf-8')
        except UnicodeEncodeError:
            return None

        return AccessKey(user_id, token)

    def generate(self, data):
        if not isinstance(data, AccessKey):
            raise InvalidArgumentError

        if not isinstance(data.token, bytes):
            raise InvalidArgumentError

        if len(data.token) != self.token_length:
            raise InvalidArgumentError

        data = data.token + data.user_id.encode('utf-8')

        iv = Random.get_random_bytes(AES.block_size)
        cipher = AES.new(self.encryption_key, AES.MODE_CFB, iv)

        data = cipher.encrypt(data)

        data = iv + data

        the_hmac = hmac.new(
            self.authentication_key,
            digestmod=hashlib.sha256,
            msg=data).digest()

        data = the_hmac + data

        data = base64.b64encode(data, b'_.').decode('ascii')

        return data


class Counterfoil:
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


class InvalidArgumentError(BaseException):
    pass


class LiteralValueSerializer:
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
                 secret=None,
                 from_header='X-Access-Key',
                 to_header='X-Set-Access-Key',
                 from_cookie='access_key',
                 counterfoil_checker=None,
                 callback=None):
        if redis_url is None:
            raise InvalidArgumentError

        self._token_length = token_length

        if secret is None:
            secret = os.urandom(64)
        if isinstance(secret, str):
            self._secret = secret.encode('utf-8')
        else:
            self._secret = secret

        self._access_key_algorithm = AccessKeyAlgorithm(self._secret, self._token_length)

        self._from_header = from_header
        self._to_header = to_header
        self._from_cookie = from_cookie
        if self._from_cookie is not None:
            if isinstance(self._from_cookie, CookieProfile):
                self._cookie_profile = self._from_cookie
            else:
                self._cookie_profile = CookieProfile(self._from_cookie, serializer=LiteralValueSerializer)

        self._connection_pool = redis.ConnectionPool.from_url(redis_url)

        self._counterfoil_checker = counterfoil_checker \
            if counterfoil_checker is not None else \
            lambda request, last_address, last_user_agent: True
        self._callback = callback \
            if callback is not None else \
            lambda userid, request: []

        self._request_properties = {}

    @staticmethod
    def from_settings(settings):
        defkwargs = {}

        argnames = [
            'redis_url',
            'token_length',
            'secret',
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

    def _free_properties(self, request_id):
        if request_id in self._request_properties:
            del self._request_properties[request_id]

    def _get_properties(self, request):
        req_id = id(request)

        if req_id in self._request_properties:
            return self._request_properties[req_id]
        else:
            finalize(request, self._free_properties, req_id)
            properties = {}
            self._request_properties[req_id] = properties
            return properties

    def _get_property(self, request, name, loader):
        request_properties = self._get_properties(request)

        if name in request_properties:
            return request_properties[name]

        value = loader()
        request_properties[name] = value
        return value

    def _load_access_key(self, request):
        def do_load():
            access_key = None

            if access_key is None:
                if self._from_header is not None:
                    access_key = request.headers.get(self._from_header, None)

            if access_key is None:
                if self._from_cookie is not None:
                    access_key = self._cookie_profile(request).get_value()

            if access_key is None:
                return None

            return self._access_key_algorithm.load(access_key)

        return self._get_property(request, 'access_key', do_load)

    def _load_counterfoil(self, request, access_key):
        def do_load():
            if access_key is None:
                return None

            redis_server = self._get_redis()
            counterfoil = redis_server.get(access_key.token)

            if counterfoil is None:
                return None

            try:
                counterfoil = pickle.loads(counterfoil)  # type: Counterfoil
            except pickle.UnpicklingError:
                return None

            if counterfoil.user_id != access_key.user_id:
                self.revoke_token(access_key.token)
                return None

            updated = False

            if counterfoil.last_user_agent != request.user_agent:
                counterfoil.last_user_agent = request.user_agent
                updated = True

            if counterfoil.last_address != request.client_addr:
                counterfoil.last_address = request.client_addr
                updated = True

            if updated:
                redis_server.set(access_key.token, pickle.dumps(counterfoil), ex=counterfoil.timeout)
            else:
                redis_server.expire(access_key.token, counterfoil.timeout)

            return counterfoil

        return self._get_property(request, 'counterfoil', do_load)

    def _push_access_key(self, request, access_key, timeout):
        access_key = self._access_key_algorithm.generate(access_key)

        headers = []

        if self._to_header is not None:
            headers.append((self._to_header, access_key))

        if self._from_cookie is not None:
            cookie_settings = {'max_age': timeout}

            headers += self._cookie_profile(request).get_headers(access_key, **cookie_settings)
        return headers

    def _reset_access_key(self, request):
        headers = []

        if self._to_header is not None:
            headers.append((self._to_header, ''))

        if self._from_cookie is not None:
            headers += self._cookie_profile(request).get_headers(None)

        return headers

    def authenticated_userid(self, request):
        counterfoil = self._load_counterfoil(request, self._load_access_key(request))

        if counterfoil is None:
            return None

        return counterfoil.user_id

    def unauthenticated_userid(self, request):
        access_key = self._load_access_key(request)

        if access_key is None:
            return None

        return access_key.user_id

    def effective_principals(self, request):
        principals = [Everyone]

        access_key = self._load_access_key(request)
        counterfoil = self._load_counterfoil(request, access_key)

        if counterfoil is not None:
            principals.append(Authenticated)
            principals.append('user:{}'.format(counterfoil.user_id))
            principals.append('token:{}'.format(binascii.hexlify(access_key.token)))
            principals += self._callback(counterfoil.user_id, request)

        return principals

    def remember(self,
                 request,
                 userid,
                 timeout=None,
                 callback=None):
        if timeout is None:
            timeout = 7 * 24 * 60 * 60

        user_id = str(userid)

        authenticated_userid = self.authenticated_userid(request)

        if authenticated_userid == user_id:
            return []

        if authenticated_userid is not None:
            _, token = self._load_access_key(request)
            self.revoke_token(token)

        counterfoil = Counterfoil(user_id, timeout)

        token = None
        redis_server = self._get_redis()
        redis_response = None
        while redis_response is None:
            token = Random.get_random_bytes(self._token_length)
            redis_response = redis_server.set(token, pickle.dumps(counterfoil), ex=counterfoil.timeout, nx=True)

        if callback is not None:
            callback(token)

        return self._push_access_key(request, AccessKey(user_id, token), timeout)

    def forget(self, request):
        access_key = self._load_access_key(request)

        if access_key is None:
            return []

        token = access_key[1]

        if token is not None:
            self.revoke_token(token)

        return self._reset_access_key(request)

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

        counterfoil = pickle.loads(counterfoil)  # type: Counterfoil
        if counterfoil.user_id != userid:
            return False

        return True


def get_token_manager(request) -> RedisTokenAuthenticationPolicy:
    return request.registry.getUtility(ITokenManager)


def set_token_manager(config, token_manager):
    config.registry.registerUtility(token_manager, ITokenManager)


def includeme(config):
    config.add_directive('set_token_manager', set_token_manager)
