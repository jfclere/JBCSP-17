# JBCSP-17
module to test ssl_variables from mod_ssl

to build:
apxs -c mod_test_ssl.c
to build and install:
home/jfclere/APACHE/bin/apxs -i -a -c mod_test_ssl.c
