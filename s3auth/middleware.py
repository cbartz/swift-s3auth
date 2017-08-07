# Copyright 2017 Christopher Bartz <bartz@dkrz.de>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from functools import partial
from hashlib import sha1
import hmac
import json
from traceback import format_exc
from urllib import quote

from swift.common.swob import HTTPBadRequest, HTTPCreated, HTTPForbidden,\
    HTTPInternalServerError, HTTPNoContent, HTTPNotFound, HTTPOk,\
    HTTPUnauthorized, wsgify
from swift.common.utils import cache_from_env, get_logger, split_path
from swift.common.wsgi import make_pre_authed_request

MEMCACHE_KEY_FORMAT = '%s/s3auth/%s'
HKEY_HASH_KEY = 'X-Account-Meta-Hash-Key'
HKEY_HASHED_ADMIN_KEY = 'X-Account-Meta-Hashed-Admin-Key'


def _hash_msg(msg, hash_key):
    """Return sha1 hash for given message."""
    return hmac.new(hash_key, msg, sha1).hexdigest()


def _denied_response(req):
    """Return a 403 or 401 Response depending on REMOTE_USER."""
    if req.remote_user:
        return HTTPForbidden(request=req)
    else:
        return HTTPUnauthorized(request=req)


def _require_s3auth_admin(f):
    """ Decorator which checks if user is s3auth admin."""

    def inner(*args, **kwargs):
        self = args[0]
        req = args[1]

        key1 = req.headers.get('x-s3auth-admin-key')
        if not key1:
            return HTTPBadRequest(
                body='x-s3auth-admin-key header required',
                request=req)

        path = quote('/v1/{}'.format(self.auth_account))
        resp = make_pre_authed_request(
            req.environ, 'HEAD', path).get_response(self.app)
        if resp.status_int // 100 != 2:
            raise Exception('Could not HEAD account: {} {}'.format(
                path, resp.status_int))
        hashed_key2 = resp.headers.get(HKEY_HASHED_ADMIN_KEY)
        hash_key = resp.headers[HKEY_HASH_KEY].encode('utf-8')

        if _hash_msg(key1, hash_key) == hashed_key2:
            return f(*args, **kwargs)
        else:
            return _denied_response(req)

    inner.__doc__ = f.__doc__
    inner.__repr__ = f.__repr__
    return inner


class S3Auth(object):
    def __init__(self, app, conf):
        self.app = app
        self.logger = get_logger(conf, log_route='s3auth')
        self.auth_prefix = conf.get('auth_prefix', '/s3auth/')
        if not self.auth_prefix:
            self.auth_prefix = '/s3auth/'
        if self.auth_prefix[0] != '/':
            self.auth_prefix = '/' + self.auth_prefix
        if self.auth_prefix[-1] != '/':
            self.auth_prefix += '/'
        self.reseller_prefix = (conf.get('reseller_prefix', 'AUTH_').
                                rstrip('_') + '_')
        self.auth_account = "{}.s3auth".format(self.reseller_prefix)
        self.akd_container_url = '/v1/{}/akeydetails/'.format(
            self.auth_account
        )
        self.prep_key = conf.get('prep_key')
        cache_time = conf.get('memcache_time', 60 * 10)
        try:
            self.cache_time = float(cache_time)
        except ValueError:
            raise ValueError(
                'value %s for memcache_time option must be a float',
                cache_time)

    def _authorize(self, req):
        """
        Authorize swift request. Used e.g. by proxy-server.
        :return: None if authorized, otherwise Response
        """
        try:
            version, account, container, obj = split_path(
                req.path, 1, 4, True)
        except ValueError:
            return _denied_response(req)

        if not account or not account.startswith(self.reseller_prefix):
            return _denied_response(req)

        if req.remote_user == account and \
                (req.method not in ('DELETE', 'PUT') or container):
            # If the user is admin for the account and is not trying to do an
            # account DELETE or PUT...
            req.environ['swift_owner'] = True
            return None

        return _denied_response(req)

    @wsgify
    def __call__(self, req):
        """Accept a standard WSGI app call.

        The call takes one of two paths:

        - Handle a request to the auth system (e.g. creating
        new access keys or changing a secret key).

        - Authenticate a request which is signed with a s3 signature.
        """
        try:
            if req.path_info.startswith(self.auth_prefix):
                return self.handle_auth_api(req)

            if 'swift3.auth_details' in req.environ:
                auth_details = req.environ['swift3.auth_details']
                akey = auth_details['access_key']
                secret, account = self._get_details(req, akey)
                if secret:
                    # Authentication.
                    if auth_details['check_signature'](secret.encode('utf-8')):
                        req.environ['swift.authorize_override'] = True
                        # Authorization function (used later in pipeline).
                        req.environ['swift.authorize'] = self._authorize
                        req.remote_user = account
                        # swift3 sets account to access_key . Replace.
                        req.environ['PATH_INFO'] = req.environ['PATH_INFO'].\
                            replace(akey, account, 1)
                    else:
                        return _denied_response(req)
                else:
                    return _denied_response(req)
        except Exception:
            self.logger.error(
                'EXCEPTION occured: %s: %s', format_exc(), req.environ)
            return HTTPInternalServerError(request=req)

        return self.app

    def _get_details(self, req, access_key):
        """Get access key details.

        :return: (secret_key, account) as tuple or (None, None) if not found.
        """
        memcache_client = cache_from_env(req.environ)
        if memcache_client:
            memcache_key = MEMCACHE_KEY_FORMAT % (
                self.reseller_prefix, access_key)
            data = memcache_client.get(memcache_key)
            if data:
                return data[0], data[1]

        path = quote(self.akd_container_url + access_key)
        resp = make_pre_authed_request(req.environ, 'GET',
                                       path).get_response(self.app)
        if resp.status_int // 100 == 2:
            data = json.loads(resp.body)
            secret_key, account = data['secret_key'], data['account']
            if memcache_client:
                memcache_client.set(memcache_key, (secret_key, account),
                                    time=self.cache_time)
            return secret_key, account
        elif resp.status_int // 100 == 4:
            return None, None
        else:
            raise Exception('Could not GET access key details: {} {}'.format(
                path, resp.status_int))

    def _set_details(self, req, access_key, secret_key, account):
        """Set access key details."""
        path = quote(self.akd_container_url + access_key)
        resp = make_pre_authed_request(
            env=req.environ,
            method='PUT',
            path=path,
            body=json.dumps({'secret_key': secret_key, 'account': account})).\
            get_response(self.app)

        if resp.status_int // 100 == 2:
            # Remove old data from cache.
            memcache_client = cache_from_env(req.environ)
            if memcache_client:
                memcache_key = MEMCACHE_KEY_FORMAT % (self.reseller_prefix,
                                                      access_key)
                memcache_client.delete(memcache_key)
        else:
            raise Exception(
                'Could not PUT access key details: {} {}'.format(
                    path, resp.status_int))

    def handle_auth_api(self, req):
        """Decide which handler to use for auth API request.

        =============================== ======  ===================
        Path                            method  handler
        =============================== ======  ===================
        /.prep                          POST    :meth:`handle_prep`
        /access_key/<access_key>        DELETE  :meth:`handle_delete_access_key`
        /access_key/<access_key>        GET     :meth:`handle_get_access_key`
        /access_key/<access_key>        PUT     :meth:`handle_put_access_key`
        /access_key/                    GET     :meth:`handle_get_listing`
        /change_secret_key/<access_key> POST    :meth:`handle_change_secret_key`
        =============================== ======  ===================
        Note: All paths have to be prefixed by `/<auth_prefix>/v1`
        """
        try:
            auth_prefix, version, rtype, access_key = split_path(
                req.path_info, 1, 4)
        except ValueError:
            return HTTPNotFound(request=req)

        handler = None
        if version == 'v1':
            if req.method == 'DELETE':
                if rtype == 'access_key' and access_key:
                    handler = partial(self.handle_delete_access_key,
                                      access_key=access_key)
            if req.method == 'GET':
                if rtype == 'access_key' and access_key:
                    handler = partial(self.handle_get_access_key,
                                      access_key=access_key)
                if rtype == 'access_key' and not access_key:
                    handler = self.handle_get_listing
            if req.method == 'PUT':
                if rtype == 'access_key' and access_key:
                    handler = partial(self.handle_put_access_key,
                                      access_key=access_key)
            if req.method == 'POST':
                if rtype == '.prep':
                    handler = self.handle_prep
                if rtype == 'change_secret_key' and access_key:
                    handler = partial(self.handle_change_secret_key,
                                      access_key=access_key)
        if not handler:
            return HTTPNotFound(request=req)

        return handler(req)

    @_require_s3auth_admin
    def handle_delete_access_key(self, req, access_key):
        """Delete access key.

        Required headers:
         - `x-s3auth-admin-key`: admin key
        """
        path = quote(self.akd_container_url + access_key)
        resp = make_pre_authed_request(req.environ, 'DELETE',
                                       path).get_response(self.app)

        if resp.status_int // 100 == 2:
            memcache_client = cache_from_env(req.environ)
            if memcache_client:
                memcache_key = MEMCACHE_KEY_FORMAT % (self.reseller_prefix,
                                                      access_key)
                memcache_client.delete(memcache_key)
            return HTTPNoContent(request=req)
        elif resp.status_int // 100 == 4:
            return HTTPNotFound(request=req)
        else:
            raise Exception(
                'Could not DELETE access key details: {} {}'.format(
                    path, resp.status_int))

    @_require_s3auth_admin
    def handle_get_access_key(self, req, access_key):
        """Get auth details of access key.

        Required headers:
         - `x-s3auth-admin-key`: admin key

        :return: JSON: {"secret_key": secret_key, "account": account}
        """
        secret_key, account = self._get_details(req, access_key)
        if secret_key:
            return HTTPOk(body=json.dumps(
                {'secret_key': secret_key, 'account': account}))
        else:
            return HTTPNotFound(request=req)

    @_require_s3auth_admin
    def handle_put_access_key(self, req, access_key):
        """Create auth details of access key.

        Required headers:
         - `x-s3auth-secret-key`: secret key to store
         - `x-s3auth-account`: account to store
         - `x-s3auth-admin-key`: admin key
        """
        secret_key = req.headers.get('x-s3auth-secret-key')
        account = req.headers.get('x-s3auth-account')
        if not (secret_key and account):
            return HTTPBadRequest(
                body='x-s3auth-secret-key and x-s3auth-account '
                     'headers required',
                request=req
            )
        self._set_details(req, access_key, secret_key, account)
        return HTTPCreated(request=req)

    @_require_s3auth_admin
    def handle_get_listing(self, req):
        """Retrieve a new-line separated list of all access keys.

        Required headers:
         - `x-s3auth-admin-key`: admin key
         """
        path = quote(self.akd_container_url)
        resp = make_pre_authed_request(req.environ, 'GET',
                                       path).get_response(self.app)

        if resp.status_int // 100 == 2:
            return HTTPOk(request=req, body=resp.body)
        else:
            raise Exception(
                'Could not GET access key listing: {} {}'.format(
                    path, resp.status_int))

    def handle_prep(self, req):
        """Prepare the backing store Swiftcluster for use with the auth system.

        Required headers:
         - `x-s3auth-prep-key`: must be same as key in config
         - `x-s3auth-hash-key`: hash key used for hashing admin key
         - `x-s3auth-admin-key`: admin key

        Note: The call can also be used to change current s3auth-admin key.
        """
        prep_key = req.headers.get("x-s3auth-prep-key")
        hash_key = req.headers.get("x-s3auth-hash-key")
        admin_key = req.headers.get('x-s3auth-admin-key')

        if not all((prep_key, hash_key, admin_key)):
            return HTTPBadRequest(
                body='Headers x-s3auth-prep-key, x-s3auth-hash-key, '
                     'x-s3auth-admin-key all required',
                request=req
            )
        if self.prep_key != prep_key:
            return _denied_response(req)

        hashed_admin_key = _hash_msg(admin_key, hash_key)
        path = quote('/v1/{}'.format(self.auth_account))
        resp = make_pre_authed_request(
            req.environ, 'PUT', path,
            headers={HKEY_HASH_KEY: hash_key,
                     HKEY_HASHED_ADMIN_KEY: hashed_admin_key,
                     }).get_response(self.app)

        if resp.status_int // 100 != 2:
            raise Exception('Could not PUT auth account: {} {}'.format(
                path, resp.status))

        path = quote(self.akd_container_url)
        resp = make_pre_authed_request(
            req.environ, 'PUT', path).get_response(self.app)
        if resp.status_int // 100 != 2:
            raise Exception(
                'Could not PUT access key details container: {} {}'.format(
                    path, resp.status))

        return HTTPOk(request=req)

    def handle_change_secret_key(self, req, access_key):
        """Change current secret key for given access key.

        Required headers:
         - `x-s3auth-secret-key-old`: must match current secret key
         - `x-s3auth-secret-key-new`: the new secret key
        """
        secret_old = req.headers.get('x-s3auth-secret-key-old')
        secret_new = req.headers.get('x-s3auth-secret-key-new')

        if not (secret_old and secret_new):
            return HTTPBadRequest(
                body='x-s3auth-secret-key-old and x-s3auth-secret-key-new '
                     'headers required',
                request=req
            )

        secret_key, account = self._get_details(req, access_key)
        if secret_key:
            if secret_key == secret_old:
                self._set_details(req, access_key, secret_new, account)
                return HTTPNoContent(request=req)
            else:
                return _denied_response(req)
        else:
            return _denied_response(req)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return S3Auth(app, conf)

    return auth_filter
