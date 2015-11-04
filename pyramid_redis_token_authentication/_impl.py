import pickle
import redis
from zope.interface import implementer, Interface
from pyramid.interfaces import IAuthenticationPolicy, IAuthorizationPolicy
from pyramid.security import Everyone, Authenticated
from random import randint


def token_generator():
    s = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join([s[randint(0, len(s) - 1)] for i in range(20)])


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
                 sesskey='auth',
                 counterfoil_checker=None,
                 callback=None):
        self._sesskey = sesskey
        self._connpool = redis.ConnectionPool.from_url(redisurl)
        self._counterfoil_checker = counterfoil_checker \
            if counterfoil_checker is not None else \
            lambda request, last_address, last_user_agent: True
        self._callback = callback \
            if callback is not None else \
            lambda userid, request: []

    def _get_redis(self):
        return redis.Redis(connection_pool=self._connpool)

    def _get_auth_record(self, request, create=False):
        if create and self._sesskey not in request.session:
            request.session[self._sesskey] = {}

        if self._sesskey in request.session:
            return _AuthRecord(request.session, self._sesskey)
        else:
            return None

    def _clean_authinfo(self, request):
        del request.session[self._sesskey]

    def authenticated_userid(self, request):
        for principal in request.effective_principals:
            if principal.startswith('user:'):
                return principal[len('user:'):]

        return None

    def unauthenticated_userid(self, request):
        info = self._get_auth_record(request)

        if info is None:
            return None

        # there is a authentication record in session
        return info.user_id

    def effective_principals(self, request):
        principals = [Everyone]
        info = self._get_auth_record(request)
        if info is None:
            return principals  # common principals

        # there is a authentication record in session
        redis_server = self._get_redis()
        counterfoil = redis_server.get(info.token)

        if counterfoil is None:
            return principals  # common principals

        # there is a counterfoil in Redis for user's token
        try:
            counterfoil = pickle.loads(counterfoil)  # type: _Counterfoil
        except pickle.UnpicklingError:
            self.forget(request)
            return principals

        if counterfoil.user_id != info.user_id:
            self.forget(request)
            return principals

        if not self._counterfoil_checker(request, counterfoil.last_address, counterfoil.last_user_agent):
            self.forget(request)
            return principals

        # the counterfoil belongs to the user
        principals.append(Authenticated)
        principals.append('user:{}'.format(counterfoil.user_id))
        principals.append('token:{}'.format(info.token))
        principals += [additional_principal
                       for principal in principals
                       for additional_principal in self._callback(principal, request)]

        update = False

        if counterfoil.last_user_agent != request.user_agent:
            counterfoil.last_user_agent = request.user_agent
            update = True

        if counterfoil.last_address != request.client_addr:
            counterfoil.last_address = request.client_addr
            update = True

        if update:
            redis_server.set(info.token, pickle.dumps(counterfoil), ex=counterfoil.timeout)
        else:
            redis_server.expire(info.token, counterfoil.timeout)

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

        userid = str(userid)

        info = self._get_auth_record(request, create=True)  # type: _AuthRecord

        if info.user_id != userid:
            redis_server.delete(info.token)
            info.token = None

        info.user_id = userid

        if info.token is not None:
            counterfoil = redis_server.get(info.token)
            if counterfoil is None:
                info.token = None
            else:
                try:
                    counterfoil = pickle.loads(counterfoil)  # type: _Counterfoil
                    if counterfoil.user_id == info.user_id:
                        counterfoil.timeout = timeout
                        redis_server.set(info.token, pickle.dumps(counterfoil), ex=counterfoil.timeout)
                    else:
                        redis_server.delete(info.token)
                        info.token = None
                except pickle.UnpicklingError:
                    redis_server.delete(info.token)
                    info.token = None

        if info.token is None:
            counterfoil = _Counterfoil(userid, timeout)

            ret = None
            token = None
            while ret is None:
                token = the_token_generator()
                ret = redis_server.set(token, pickle.dumps(counterfoil), ex=counterfoil.timeout, nx=True)
            info.token = token

        if info.token is not None:
            callback(info.token)

        return []

    def forget(self, request):
        info = self._get_auth_record(request)
        if info is not None:
            self.revoke_token(info.token)
            self._clean_authinfo(request)

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


def get_token_manager(request) -> RedisTokenAuthenticationPolicy:
    return request.registry.getUtility(ITokenManager)


def includeme(config):
    authentication_policy = RedisTokenAuthenticationPolicy(config.get_settings()['redis.authentication.url'])
    config.set_authentication_policy(authentication_policy)

    def register_token_manager():
        config.registry.registerUtility(authentication_policy, ITokenManager)
    config.action('register_token_manager', register_token_manager)
