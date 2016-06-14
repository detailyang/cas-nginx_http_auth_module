
/*
 * Copyright (C) Maxim Dounin
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define CAS_HEADER_AUTHORIZATION "Basic realm=\"<CAS SERVER>\""
#define CAS_HEADER_USERNAME "cas-username"
#define CAS_HEADER_PASSWORD "cas-password"
#define CAS_VARIABLE "cas_username"


typedef struct {
    ngx_str_t                 uri;
} ngx_http_cas_conf_t;


typedef struct {
    ngx_str_t                 username;
    ngx_uint_t                done;
    ngx_uint_t                status;
    ngx_http_request_t       *subrequest;
} ngx_http_cas_ctx_t;


static ngx_int_t ngx_http_cas_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cas_done(ngx_http_request_t *r, void *data, ngx_int_t rc);
static void * ngx_http_cas_create_conf(ngx_conf_t *cf);
static char * ngx_http_cas_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_cas_init(ngx_conf_t *cf);
static char * ngx_http_cas_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_cas_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_http_cas_commands[] = {

    { ngx_string("cas_request"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_cas_request,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_http_cas_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_cas_init,                     /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    ngx_http_cas_create_conf,              /* create location configuration */
    ngx_http_cas_merge_conf                /* merge location configuration */
};


ngx_module_t  ngx_http_cas_module = {
    NGX_MODULE_V1,
    &ngx_http_cas_module_ctx,     /* module context */
    ngx_http_cas_commands,        /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_cas_handler(ngx_http_request_t *r)
{
    ngx_str_t                      username, password;
    ngx_str_t                      plain, encrypt;
    ngx_uint_t                     i;
    ngx_table_elt_t               *h;
    ngx_http_request_t            *sr;
    ngx_http_cas_ctx_t            *ctx;
    ngx_http_cas_conf_t           *hccf;
    ngx_http_post_subrequest_t    *ps;

    hccf = ngx_http_get_module_loc_conf(r, ngx_http_cas_module);
    if (hccf->uri.len == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_cas_module);

    if (ctx != NULL) {
        sr = ctx->subrequest;
        if (!ctx->done) {
            return NGX_AGAIN;
        }
        if (ctx->status == NGX_HTTP_OK) {
            return NGX_OK;
        }

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        h->key.len = sizeof("WWW-Authenticate") - 1;
        h->key.data = (u_char *)"WWW-Authenticate";
        h->value.len = sizeof(CAS_HEADER_AUTHORIZATION) - 1;
        h->value.data = (u_char *)CAS_HEADER_AUTHORIZATION;
        r->headers_out.www_authenticate = h;

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "add header");

        return NGX_HTTP_UNAUTHORIZED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cas_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_cas_done;
    ps->data = ctx;

    if (r->headers_in.authorization) {
        encrypt.data = r->headers_in.authorization->value.data + sizeof("Basic ") - 1;
        encrypt.len = r->headers_in.authorization->value.len - sizeof("Basic ") + 1;
        plain.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(encrypt.len));
        if (plain.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_decode_base64(&plain, &encrypt) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        i = 0;
        while(i++ < plain.len) {
            if (*(plain.data+i) == ':') {
                break;
            }
        }
        username.len = i;
        username.data = plain.data;
        password.len = plain.len - i - 1;
        password.data = plain.data + username.len + 1;

        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        h->key.len = sizeof(CAS_HEADER_USERNAME) - 1;
        h->key.data = (u_char *)CAS_HEADER_USERNAME;
        h->value.len = username.len;
        h->value.data = username.data;

        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        h->key.len = sizeof(CAS_HEADER_PASSWORD) - 1;
        h->key.data = (u_char *)CAS_HEADER_PASSWORD;
        h->value.len = password.len;
        h->value.data = password.data;
    }

    if (ngx_http_subrequest(r, &hccf->uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }
    sr->header_only = 1;

    ctx->subrequest = sr;
    ngx_http_set_ctx(r, ctx, ngx_http_cas_module);

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_cas_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_uint_t            i;
    ngx_list_part_t      *part = &r->headers_out.headers.part;
    ngx_table_elt_t      *header = part->elts;
    ngx_http_cas_ctx_t   *ctx = data;


    ctx->done = 1;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }
        if (header[i].hash == 0) {
            continue;
        }

        if (0 == ngx_strncasecmp(header[i].key.data,
                (u_char *) CAS_HEADER_USERNAME,
                header[i].key.len
            ))
        {
            ctx->username.data = header[i].value.data;
            ctx->username.len = header[i].value.len;
            goto found;
        }
    }

    ctx->status = NGX_HTTP_UNAUTHORIZED;

    return rc;
found:
    ctx->status = NGX_HTTP_OK;

    return rc;
}


static void *
ngx_http_cas_create_conf(ngx_conf_t *cf)
{
    ngx_http_cas_conf_t  *hccf;

    hccf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cas_conf_t));
    if (hccf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     * hccf->uri.len = { 0, NULL };
     */

    return hccf;
}


static char *
ngx_http_cas_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cas_conf_t *prev = parent;
    ngx_http_cas_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->uri, prev->uri, "");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_cas_init(ngx_conf_t *cf)
{
    ngx_str_t                   name;
    ngx_http_variable_t        *var;
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_cas_handler;

    ngx_str_set(&name, CAS_VARIABLE);

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_cas_variable;
    var->data = (uintptr_t)cmcf;

    return NGX_OK;
}


static char *
ngx_http_cas_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cas_conf_t *hccf = conf;
    ngx_str_t        *value;

    if (hccf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;
    hccf->uri = value[1];

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_cas_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cas_ctx_t            *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cas_module);
    if (ctx == NULL) {
        goto NOT_FOUND;
    }

    v->len = ctx->username.len;
    v->data = ctx->username.data;

    return NGX_OK;

NOT_FOUND:
    v->not_found = 1;
    return NGX_OK;
}