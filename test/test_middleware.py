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

from contextlib import contextmanager
import itertools
import json
import mock
import unittest

from swift.common.swob import Request
from swift.common.swob import Response

from s3auth import middleware as auth


class FakeApp(object):

    def __init__(self, status_headers_body_iter=None):
        self.calls = 0
        self.status_headers_body_iter = status_headers_body_iter
        if not self.status_headers_body_iter:
            self.status_headers_body_iter = iter([('404 Not Found', {}, '')])

    def __call__(self, env, start_response):
        self.calls += 1
        self.request = Request.blank('', environ=env)
        if 'swift.authorize' in env:
            resp = env['swift.authorize'](self.request)
            if resp:
                return resp(env, start_response)
        status, headers, body = self.status_headers_body_iter.next()
        return Response(status=status, headers=headers,
                        body=body)(env, start_response)


class FakeMemcache(object):

    def __init__(self, store=None):
        if store is None:
            store = {}
        self.store = store

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value, timeout=0, time=0):
        self.store[key] = value
        return True

    def incr(self, key, timeout=0, time=0):
        self.store[key] = self.store.setdefault(key, 0) + 1
        return self.store[key]

    @contextmanager
    def soft_lock(self, key, timeout=0, retries=5, time=0):
        yield True

    def delete(self, key):
        try:
            del self.store[key]
        except Exception:
            pass
        return True


class TestS3Auth(unittest.TestCase):

    def req_s3_admin_iter(self, iterable):
        """Prepend correct header to output iterable.

        For requests where admin is needed.
        """
        return itertools.chain([
            ('200 Ok', {auth.HKEY_HASH_KEY: 'hkey',
                        auth.HKEY_HASHED_ADMIN_KEY: auth._hash_msg('adm_key',
                                                                   'hkey')},
             '')], iterable)

    def req_s3_admin_make_request(self, path, **kwargs):
        """Insert x-s3auth-admin-key header to request."""
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        kwargs['headers']['x-s3auth-admin-key'] = 'adm_key'
        return Request.blank(path, **kwargs)

    def setUp(self):
        conf = {'prep_key': 'prep_key'}
        self.test_auth = auth.filter_factory(conf)(FakeApp())
        self.test_auth.logger = mock.Mock()
        self.hash_key = 'hash_key'
        self.memcache = FakeMemcache({
            auth.MEMCACHE_KEY_FORMAT % ('AUTH_', 'akey'): ('skey', 'acct')})

    # Test require_s3auth_admin decorator.
    def test_req_s3_admin_success(self):
        self.test_auth.app = FakeApp(iter([
            # HEAD account.
            ('200 Ok', {auth.HKEY_HASH_KEY: 'hkey',
                        auth.HKEY_HASHED_ADMIN_KEY: auth._hash_msg('adm_key',
                                                                   'hkey')},
             '')]))
        req = Request.blank('', headers={'x-s3auth-admin-key': 'adm_key'})
        self.assertEqual(
            auth._require_s3auth_admin(lambda *args: 'check')(self.test_auth,
                                                              req), 'check')

    def test_req_s3_admin_fail_wrong_key(self):
        self.test_auth.app = FakeApp(iter([
            # HEAD account.
            ('200 Ok', {auth.HKEY_HASH_KEY: 'hkey',
                        auth.HKEY_HASHED_ADMIN_KEY: auth._hash_msg('adm_key',
                                                                   'hkey')},
             '')]))
        req = Request.blank('', headers={'x-s3auth-admin-key': 'wrong_key'})
        resp = auth._require_s3auth_admin(lambda *args: 'check')(
            self.test_auth, req)
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.status_int, 401)

    def test_req_s3_admin_fail_bad_headers(self):
        req = Request.blank('')
        resp = auth._require_s3auth_admin(lambda *args: 'check')(
            self.test_auth, req)
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.status_int, 400)
        self.assertEqual(resp.body, 'x-s3auth-admin-key header required')

        req = Request.blank('', headers={'x-s3auth-wrong-header': 'aas'})
        resp = auth._require_s3auth_admin(lambda *args: 'check')(
            self.test_auth, req)
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.status_int, 400)
        self.assertEqual(resp.body, 'x-s3auth-admin-key header required')

    def test_req_s3_admin_fail_error(self):
        self.test_auth.app = FakeApp(iter([
            # HEAD account.
            ('500 Internal Server Error', {}, '')]))
        req = Request.blank('', headers={'x-s3auth-admin-key': 'adm_key'})
        with self.assertRaises(Exception) as cm:
            auth._require_s3auth_admin(lambda *args: 'check')(self.test_auth,
                                                              req)
        self.assertEqual(
            cm.exception.message,
            'Could not HEAD account: /v1/AUTH_.s3auth 500')

    # Test _get_details with and without memcache.
    def test_get_details_success_memcache(self):
        req = Request.blank('', environ={'swift.cache': self.memcache})
        self.assertEqual(
            self.test_auth._get_details(req, 'akey'),
            ('skey', 'acct'))

    def test_get_details_success(self):
        self.test_auth.app = FakeApp(iter([
            # GET object.
            ('200 Ok', {},
             json.dumps({'secret_key': 'skey', 'account': 'acct'}))]))
        req = Request.blank('')
        self.assertEqual(
            self.test_auth._get_details(req, 'akey'),
            ('skey', 'acct'))

    def test_get_details_success_memcache_cache_miss(self):
        self.test_auth.app = FakeApp(iter([
            # GET object.
            ('200 Ok', {},
             json.dumps({'secret_key': 'skey', 'account': 'acct'}))]))
        memcache = FakeMemcache()
        req = Request.blank('', environ={'swift.cache': memcache})
        self.assertEqual(
            self.test_auth._get_details(req, 'akey'),
            ('skey', 'acct'))
        self.assertEqual(
            memcache.get(auth.MEMCACHE_KEY_FORMAT % ('AUTH_', 'akey')),
            ('skey', 'acct'))

    def test_get_details_fail_memcache_cache_miss_nfound(self):
        self.test_auth.app = FakeApp(iter([
            # GET object.
            ('404 Not found', {}, '')]))
        memcache = FakeMemcache()
        req = Request.blank('', environ={'swift.cache': memcache})
        self.assertEqual(
            self.test_auth._get_details(req, 'akey'),
            (None, None))
        self.assertEqual(
            memcache.get(auth.MEMCACHE_KEY_FORMAT % ('AUTH_', 'akey')), None)

    def test_get_details_fail_nfound(self):
        self.test_auth.app = FakeApp(iter([
            # GET object.
            ('404 Not found', {}, '')]))
        req = Request.blank('')
        self.assertEqual(
            self.test_auth._get_details(req, 'akey'),
            (None, None))

    def test_get_details_fail_error(self):
        self.test_auth.app = FakeApp(iter([
            # GET object.
            ('500 Internal Server Error', {}, '')]))
        req = Request.blank('')
        with self.assertRaises(Exception) as cm:
            self.test_auth._get_details(req, 'akey')
        self.assertEqual(
            cm.exception.message,
            'Could not GET access key details: '
            '/v1/AUTH_.s3auth/akeydetails/akey 500')

    # Test _set_details .
    def test_set_details_success(self):
        self.test_auth.app = FakeApp(iter([
            # PUT object.
            ('200 Ok', {}, '')]))
        req = Request.blank('', environ={'swift.cache': self.memcache})
        self.test_auth._set_details(req, 'akey', 'skey2', 'acct2')
        self.assertEqual(self.test_auth.app.calls, 1)
        self.assertEqual(
            self.memcache.get(auth.MEMCACHE_KEY_FORMAT % ('AUTH_', 'akey')),
            None)

    def test_set_details_fail_error(self):
        self.test_auth.app = FakeApp(iter([
            # PUT object.
            ('500 Internal Server Error', {}, '')]))
        req = Request.blank('', environ={'swift.cache': self.memcache})
        with self.assertRaises(Exception) as cm:
            self.test_auth._set_details(req, 'akey', 'skey2', 'acct2')
        self.assertEqual(
            cm.exception.message,
            'Could not PUT access key details: '
            '/v1/AUTH_.s3auth/akeydetails/akey 500')
        self.assertEqual(
            self.memcache.get(auth.MEMCACHE_KEY_FORMAT % ('AUTH_', 'akey')),
            ('skey', 'acct'))

    # Test authentication.
    @mock.patch('s3auth.middleware.S3Auth._get_details',
                mock.Mock(return_value=('skey', 'AUTH_acct')))
    def test_auth_success(self):
        req = Request.blank('/v1/akey/bucket', environ={
            'swift3.auth_details': {'access_key': 'akey',
                                    'check_signature': lambda x: x == 'skey'}
        })
        resp = req.get_response(self.test_auth)
        self.assertEqual(self.test_auth.app.calls, 1)
        self.assertEqual(req.remote_user, 'AUTH_acct')
        self.assertEqual(req.path_info, '/v1/AUTH_acct/bucket')
        self.assertEqual(resp.status_int, 404)

    @mock.patch('s3auth.middleware.S3Auth._get_details',
                mock.Mock(return_value=('wrong_key', 'AUTH_acct')))
    def test_auth_fail_wrong_key(self):
        req = Request.blank('/v1/akey', environ={
            'swift3.auth_details': {'access_key': 'akey',
                                    'check_signature': lambda x: x == 'skey'}
        })
        resp = req.get_response(self.test_auth)
        self.assertEqual(self.test_auth.app.calls, 0)
        self.assertIsNone(req.remote_user)
        self.assertEqual(resp.status_int, 401)

    @mock.patch('s3auth.middleware.S3Auth._get_details',
                mock.Mock(return_value=(None, None)))
    def test_auth_fail_nfound(self):
        req = Request.blank('/v1/akey', environ={
            'swift3.auth_details': {'access_key': 'akey',
                                    'check_signature': lambda x: x == 'skey'}
        })
        resp = req.get_response(self.test_auth)
        self.assertEqual(self.test_auth.app.calls, 0)
        self.assertIsNone(req.remote_user)
        self.assertEqual(resp.status_int, 401)

    # Test authorization.
    def test_authorize_fail_bad_path(self):
        req = Request.blank('/')
        resp = self.test_auth._authorize(req)
        self.assertEqual(resp.status_int, 401)
        req = Request.blank('/badpath')
        req.remote_user = 'account'
        resp = self.test_auth._authorize(req)
        self.assertEqual(resp.status_int, 403)

    def test_authorize_success(self):
        req = Request.blank('/v1/AUTH_cfa')
        req.remote_user = 'AUTH_cfa'
        for m in ('GET', 'HEAD', 'POST'):
            req.method = m
            self.assertEqual(self.test_auth._authorize(req), None)
            self.assertTrue(req.environ.get('swift_owner'))

        for m in ('DELETE', 'GET', 'HEAD', 'POST', 'PUT'):
            req.method = m
            for p in ('/v1/AUTH_cfa/container', '/v1/AUTH_cfa/container/obj'):
                req.path_info = p
                self.assertEqual(self.test_auth._authorize(req), None)
                self.assertTrue(req.environ.get('swift_owner'))

    def test_authorize_fail_wrong_user(self):
        req = Request.blank('/v1/AUTH_cfa')
        req.remote_user = 'AUTH_other'
        resp = self.test_auth._authorize(req)
        self.assertEqual(resp.status_int, 403)

    def test_authorize_fail_account_put_or_del(self):
        req = Request.blank('/v1/AUTH_cfa')
        req.remote_user = 'AUTH_cfa'
        for m in ('DELETE', 'PUT'):
            req.method = m
            resp = self.test_auth._authorize(req)
            self.assertEqual(resp.status_int, 403)

    # Handlers.
    def test_handler_not_found(self):
        for path, meths in (
                ('/s3auth/v1/access_key/akey', ('HEAD', 'POST')),
                ('/s3auth/v1/access_key/', ('DELETE', 'HEAD', 'POST', 'PUT')),
                ('/s3auth/v1/.prep', ('DELETE', 'GET', 'HEAD', 'PUT')),
                ('/s3auth/v1/change_secret_key',
                 ('DELETE', 'GET', 'HEAD', 'PUT'))
        ):
            for m in meths:
                resp = (Request.blank(path,
                                      environ={'REQUEST_METHOD': m}).
                        get_response(self.test_auth))
                self.assertEqual(
                    resp.status_int, 404,
                    'Return code not 404 for : %s %s' % (path, m))

    def test_handle_delete_access_key_success(self):
        self.test_auth.app = FakeApp(
            self.req_s3_admin_iter([('204 No Content', {}, '')]))
        resp = self.req_s3_admin_make_request(
            '/s3auth/v1/access_key/akey',
            environ={'REQUEST_METHOD': 'DELETE',
                     'swift.cache': self.memcache}).get_response(
            self.test_auth)
        self.assertEqual(resp.status_int, 204)
        self.assertEqual(
            self.memcache.get(auth.MEMCACHE_KEY_FORMAT % ('AUTH_', 'akey')),
            None)

    def test_handle_delete_access_key_fail_nfound(self):
        self.test_auth.app = FakeApp(
            self.req_s3_admin_iter([('404 Not Found', {}, '')]))
        resp = self.req_s3_admin_make_request(
            '/s3auth/v1/access_key/akey',
            environ={'REQUEST_METHOD': 'DELETE'}).get_response(self.test_auth)
        self.assertEqual(resp.status_int, 404)

    def test_handle_delete_access_key_fail_error(self):
        self.test_auth.app = FakeApp(
            self.req_s3_admin_iter([('500 Internal Server Error', {}, '')]))
        resp = self.req_s3_admin_make_request(
            '/s3auth/v1/access_key/akey',
            environ={'REQUEST_METHOD': 'DELETE'}).get_response(self.test_auth)
        self.assertEqual(resp.status_int, 500)
        self.assertIn(
            'Could not DELETE access key details: /v1/AUTH_.s3auth/'
            'akeydetails/akey 500',
            self.test_auth.logger.error.call_args[0][1])

    @mock.patch('s3auth.middleware.S3Auth._get_details',
                mock.Mock(return_value=('skey', 'acct')))
    def test_handle_get_access_key_success(self):
        self.test_auth.app = FakeApp(self.req_s3_admin_iter([]))
        resp = self.req_s3_admin_make_request(
            '/s3auth/v1/access_key/akey',
            environ={'REQUEST_METHOD': 'GET'}).get_response(self.test_auth)
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(resp.body, json.dumps(
            {'secret_key': 'skey', 'account': 'acct'}))
        self.assertEqual(
            auth.S3Auth._get_details.call_args_list[0][0][1], 'akey')

    @mock.patch('s3auth.middleware.S3Auth._get_details',
                mock.Mock(return_value=(None, None)))
    def test_handle_get_access_key_fail_nfound(self):
        self.test_auth.app = FakeApp(self.req_s3_admin_iter([]))
        resp = self.req_s3_admin_make_request(
            '/s3auth/v1/access_key/akey',
            environ={'REQUEST_METHOD': 'GET'}).get_response(self.test_auth)
        self.assertEqual(resp.status_int, 404)

    @mock.patch('s3auth.middleware.S3Auth._set_details', mock.Mock())
    def test_handle_put_access_key_success(self):
        self.test_auth.app = FakeApp(self.req_s3_admin_iter([]))
        resp = self.req_s3_admin_make_request(
            '/s3auth/v1/access_key/akey',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'x-s3auth-secret-key': 'skey',
                     'x-s3auth-account': 'acct'}).get_response(self.test_auth)
        self.assertEqual(resp.status_int, 201)
        self.assertEqual(
            auth.S3Auth._set_details.call_args_list[0][0][1:],
            ('akey', 'skey', 'acct'))

    @mock.patch('s3auth.middleware.S3Auth._set_details', mock.Mock())
    def test_handle_put_access_key_fail_bad_headers(self):
        def check(req):
            self.test_auth.app = FakeApp(self.req_s3_admin_iter([]))
            resp = req.get_response(self.test_auth)
            self.assertEqual(resp.status_int, 400)
            self.assertEqual(
                resp.body,
                'x-s3auth-secret-key and x-s3auth-account headers required')
            auth.S3Auth._set_details.assert_not_called()

        check(self.req_s3_admin_make_request(
            '/s3auth/v1/access_key/akey',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'x-s3auth-account': 'acct'}))

        check(self.req_s3_admin_make_request(
            '/s3auth/v1/access_key/akey',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'x-s3auth-secret-key': 'skey'}))

        check(self.req_s3_admin_make_request(
            '/s3auth/v1/access_key/akey',
            environ={'REQUEST_METHOD': 'PUT'}))

    def test_handle_listing_success(self):
        self.test_auth.app = FakeApp(self.req_s3_admin_iter([
            # Get akd container.
            ('200 Ok', {}, 'listing'),
        ]))
        resp = (self.req_s3_admin_make_request('/s3auth/v1/access_key/',
                                               environ={
                                                   'REQUEST_METHOD': 'GET'}).
                get_response(self.test_auth))
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(resp.body, 'listing')

    def test_handle_listing_fail_error(self):
        self.test_auth.app = FakeApp(self.req_s3_admin_iter(iter([
            # Get akd container.
            ('500 Internal Server Error', {}, ''),
        ])))
        resp = (self.req_s3_admin_make_request('/s3auth/v1/access_key/',
                                               environ={
                                                   'REQUEST_METHOD': 'GET'}).
                get_response(self.test_auth))
        self.assertEqual(resp.status_int, 500)
        self.assertIn(
            'Could not GET access key listing: '
            '/v1/AUTH_.s3auth/akeydetails/ 500',
            self.test_auth.logger.error.call_args[0][1])

    def test_prep_fail_bad_creds(self):
        resp = (Request.blank('/s3auth/v1/.prep',
                              environ={'REQUEST_METHOD': 'POST'},
                              headers={"x-s3auth-prep-key": 'wrong_key',
                                       'x-s3auth-admin-key': 'admin_key',
                                       'x-s3auth-hash-key': 'hash_key'}).
                get_response(self.test_auth))
        self.assertEqual(resp.status_int, 401)

    def test_prep_fail_bad_headers(self):
        def check(req):
            resp = req.get_response(self.test_auth)
            self.assertEqual(resp.status_int, 400)
            self.assertEqual(
                resp.body,
                'Headers x-s3auth-prep-key, x-s3auth-hash-key, '
                'x-s3auth-admin-key all required')

        check((Request.blank('/s3auth/v1/.prep',
                             environ={'REQUEST_METHOD': 'POST'})))

        check(Request.blank('/s3auth/v1/.prep',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={"x-s3auth-prep-key": 'prep_key'}))

        check(Request.blank('/s3auth/v1/.prep',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'x-s3auth-prep-key': 'prep_key',
                                     'x-s3auth-admin-key': 'admin_key'}))

    def test_prep_fail_account_create(self):
        self.test_auth.app = FakeApp(iter([
            # PUT of .s3auth account
            ('503 Service Unavailable', {}, '')]))
        resp = (Request.blank('/s3auth/v1/.prep',
                              environ={'REQUEST_METHOD': 'POST'},
                              headers={"x-s3auth-prep-key": 'prep_key',
                                       'x-s3auth-admin-key': 'auth_key',
                                       'x-s3auth-hash-key': 'hash_key'}).
                get_response(self.test_auth))
        self.assertEqual(resp.status_int, 500)
        self.assertEqual(self.test_auth.app.calls, 1)
        self.assertIn(
            'Could not PUT auth account: /v1/AUTH_.s3auth 503',
            self.test_auth.logger.error.call_args[0][1])

    def test_prep_fail_container_create(self):
        self.test_auth.app = FakeApp(iter([
            # PUT of .s3auth account
            ('201 Created', {}, ''),
            # PUT of akd container.
            ('503 Service Unavailable', {}, '')
        ]))
        resp = (Request.blank('/s3auth/v1/.prep',
                              environ={'REQUEST_METHOD': 'POST'},
                              headers={"x-s3auth-prep-key": 'prep_key',
                                       'x-s3auth-admin-key': 'auth_key',
                                       'x-s3auth-hash-key': 'hash_key'}).
                get_response(self.test_auth))
        self.assertEqual(resp.status_int, 500)
        self.assertEqual(self.test_auth.app.calls, 2)
        self.assertIn(
            'Could not PUT access key details container: '
            '/v1/AUTH_.s3auth/akeydetails/ 503',
            self.test_auth.logger.error.call_args[0][1])

    def test_prep_success(self):
        self.test_auth.app = FakeApp(iter([
            # PUT of .s3auth account.
            ('201 Created', {}, ''),
            # PUT of akd container.
            ('201 Created', {}, ''),
        ]))
        resp = (Request.blank('/s3auth/v1/.prep',
                              environ={'REQUEST_METHOD': 'POST'},
                              headers={"x-s3auth-prep-key": 'prep_key',
                                       'x-s3auth-admin-key': 'auth_key',
                                       'x-s3auth-hash-key': 'hash_key'}).
                get_response(self.test_auth))
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(self.test_auth.app.calls, 2)

    @mock.patch('s3auth.middleware.S3Auth._get_details',
                mock.Mock(return_value=('skey', 'AUTH_acct')))
    @mock.patch('s3auth.middleware.S3Auth._set_details', mock.Mock())
    def test_change_secret_key_success(self):
        req = Request.blank(
            '/s3auth/v1/change_secret_key/akey',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'x-s3auth-secret-key-old': 'skey',
                     'x-s3auth-secret-key-new': 'new'}
        )
        resp = req.get_response(self.test_auth)
        self.assertEqual(resp.status_int, 204)
        self.assertEqual(
            auth.S3Auth._set_details.call_args_list[0][0][1:],
            ('akey', 'new', 'AUTH_acct'))

    @mock.patch('s3auth.middleware.S3Auth._get_details',
                mock.Mock(return_value=('skey', 'AUTH_acct')))
    @mock.patch('s3auth.middleware.S3Auth._set_details', mock.Mock())
    def test_change_secret_key_fail_wrong_key(self):
        req = Request.blank(
            '/s3auth/v1/change_secret_key/akey',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'x-s3auth-secret-key-old': 'wrong_key',
                     'x-s3auth-secret-key-new': 'new'}
        )
        resp = req.get_response(self.test_auth)
        self.assertEqual(resp.status_int, 401)
        auth.S3Auth._set_details.assert_not_called()

    @mock.patch('s3auth.middleware.S3Auth._get_details',
                mock.Mock(return_value=(None, None)))
    @mock.patch('s3auth.middleware.S3Auth._set_details', mock.Mock())
    def test_change_secret_key_fail_nfound(self):
        req = Request.blank(
            '/s3auth/v1/change_secret_key/akey',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'x-s3auth-secret-key-old': 'skey',
                     'x-s3auth-secret-key-new': 'new'}
        )
        resp = req.get_response(self.test_auth)
        self.assertEqual(resp.status_int, 401)
        auth.S3Auth._set_details.assert_not_called()

    @mock.patch('s3auth.middleware.S3Auth._set_details', mock.Mock())
    def test_change_secret_key_fail_bad_headers(self):
        def check(req):
            resp = req.get_response(self.test_auth)
            self.assertEqual(resp.status_int, 400)
            self.assertEqual(
                resp.body,
                'x-s3auth-secret-key-old and x-s3auth-secret-key-new '
                'headers required'
            )
            auth.S3Auth._set_details.assert_not_called()

        check(Request.blank(
            '/s3auth/v1/change_secret_key/akey',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'x-s3auth-secret-key-new': 'skey'}
        ))

        check(Request.blank(
            '/s3auth/v1/change_secret_key/akey',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'x-s3auth-secret-key-old': 'skey'}
        ))

        check(Request.blank(
            '/s3auth/v1/change_secret_key/akey',
            environ={'REQUEST_METHOD': 'POST'},
        ))


if __name__ == '__main__':
    unittest.main()
