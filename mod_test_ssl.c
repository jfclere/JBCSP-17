#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_ssl.h"

static APR_OPTIONAL_FN_TYPE(ssl_hook_GetVars) *test_ssl_hook_GetVars = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *test_var_ssl_lookup = NULL;


static int test_ssl_init(apr_pool_t *p, apr_pool_t *plog,
apr_pool_t *ptemp, server_rec *s)
{
    test_ssl_hook_GetVars = APR_RETRIEVE_OPTIONAL_FN(ssl_hook_GetVars);
    test_var_ssl_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
    return OK;
}

static int test_ssl_trans(request_rec *r)
{
   const char *const *var;
   if (test_ssl_hook_GetVars == NULL)
       var = NULL;
   else
       var = test_ssl_hook_GetVars();
   if (var == NULL) {
       ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                    "No SSL variables");
       return DECLINED;
   }
   while (*var != NULL) {
       /* list and read variable */
       if (test_var_ssl_lookup) {
           const char *val = test_var_ssl_lookup(r->pool, r->server,
                                                 r->connection, r, (char *)*var);
           if (val && val[0])
               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                            "SSL variable: %s : %s", *var, val);
           else 
               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                            "SSL variable: %s : (null)", *var);
       } else {
           ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                        "SSL variable: %s", *var);
       }
       var++;
   }
   return DECLINED;
}

static void test_ssl_hooks(apr_pool_t *p)
{
   ap_hook_post_config(test_ssl_init, NULL, NULL, APR_HOOK_MIDDLE);

   ap_hook_translate_name(test_ssl_trans, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Module declaration */

module AP_MODULE_DECLARE_DATA test_ssl_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    test_ssl_hooks      /* register hooks */
};
