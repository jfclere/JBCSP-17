#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

static const char *const *ssl_hook_Fixup_vars;


static int test_ssl_init(apr_pool_t *p, apr_pool_t *plog,
apr_pool_t *ptemp, server_rec *s)
{
    ssl_hook_Fixup_vars = ap_lookup_provider("mod_ssl" , "ssl_variables", "0");
    return OK;
}

static int test_ssl_trans(request_rec *r)
{
   const char *const *var = ssl_hook_Fixup_vars;
   if (var == NULL) {
       ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                    "No SSL variables");
       return DECLINED;
   }
   while (*var != NULL) {
       /* list and read variable */
       ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                    "SSL variable: %s", *var);
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