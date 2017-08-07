swift-s3auth
------------
`swift-s3auth` is a lightweight auth middleware which stores credentials inside
OpenStack Swift itself (inspired by [swauth](https://github.com/openstack/swauth)).
The middleware can be used with your already deployed auth middleware in use.
This is useful, if your current auth middleware does not support s3 
(e.g. because passwords are not stored in plaintext).

Quick Start Guide
-----------------

1) Install s3auth with ``sudo python setup.py install`` or ``sudo python
   setup.py develop``.

2) Alter your proxy-server.conf pipeline and place s3auth between swift3 and your
   auth middleware in use:

        [pipeline:main]
        pipeline = catch_errors cache swift3 s3auth myauth proxy-server


3) Add to your proxy-server.conf the section for the Swauth WSGI filter:

        [filter:s3auth]
        use = egg:s3auth#s3auth
        prep_key = prepkey
        #Following are optional. Default values are displayed on the right side.
        #auth_prefix = s3auth
        #reseller_prefix = AUTH_
        #memcache_time= 600

4) Restart your proxy server.

6) Initialize the Swift3 backing store in Swift. E.g. with curl:

       curl -i -H"X-s3auth-prep-key: myprepkey" -H"x-s3auth-hash-key: myhash"\
       -H"x-s3auth-admin-key: admkey" -XPOST "http://cluster:8080/s3auth/v1/.prep"

7) After successful initialization, remove the prep_key from the proxy-server.conf
   for better security.

8) Add an access key. You need to specify the secret key for the access key and
   the swift storage account which the key should map to:
   
       curl -i -H"x-s3auth-account: AUTH_acct" -H"x-s3auth-secret-key: skey"\
       -H"x-s3auth-admin-key: admkey" -XPUT "http://cluster:8080/s3auth/v1/access_key/akey"

9) Ensure it works with your favourite s3client. E.g. [s3curl](https://github.com/rtdp/s3curl):

       s3curl.pl --key skey --id akey http://cluster:8080/

10) Read the API [docs](http://swift-s3auth.readthedocs.io/en/latest/middleware.html).