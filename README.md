# ngx_http_cas_module
A component for nginx module integrated with [CAS](https://github.com/detailyang/cas-server)


# ngx http barcode module
![Branch master](https://img.shields.io/badge/branch-master-brightgreen.svg?style=flat-square)[![Build](https://api.travis-ci.org/detailyang/cas-nginx_http_auth_module.svg)](https://travis-ci.org/detailyang/cas-nginx_http_auth_module)[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/detailyang/cas-nginx_http_auth_module/master/LICENSE)[![release](https://img.shields.io/github/release/detailyang/cas-nginx_http_auth_module.svg)](https://github.com/detailyang/cas-nginx_http_auth_module/releases)


Table of Contents
-----------------
* [How-To-Use](#how-to-use)
* [Requirements](#requirements)
* [Direction](#direction)
* [Contributing](#contributing)
* [Author](#author)
* [License](#license)


How-To-Use
----------------

ngx_http_cas_module is the same as ngx_http_auth_module but for [CAS](https://github.com/detailyang/cas-server)
For example:

```bash
location / {
        cas_request /auth;
        proxy_pass http://127.0.0.1:12345;
}

location = /auth {
        internal;
        rewrite .* /public/users/login break;
        proxy_pass https://cas.example.com;
}
```

Requirements
------------

ngx_http_barcode requires the following to run:

 * [nginx](http://nginx.org/) or other forked version like [openresty](http://openresty.org/)、[tengine](http://tengine.taobao.org/)
 * [CAS](https://github.com/detailyang/cas-server)

Direction
------------

* cas_request: enable cas authentication
Syntax:     cas_request url
Default:    -
Context:    server|location

```
location / {
        cas_request /auth;
        proxy_pass http://127.0.0.1:12345;
}

location = /auth {
        internal;
        rewrite .* /public/users/login break;
        proxy_pass https://cas.example.com;
}
```
PS: you can use $remote_user in access_log to record username

Contributing
------------

To contribute to ngx_http_cas_module, clone this repo locally and commit your code on a separate branch.


Author
------

> GitHub [@detailyang](https://github.com/detailyang)


License
-------
ngx_http_barcode is licensed under the [MIT] license.

[MIT]: https://github.com/detailyang/ybw/blob/master/licenses/MIT
