/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../e_os.h"
#include <openssl/evp.h>
#include <openssl/sha.h>

#ifdef CHARSET_EBCDIC
# include <openssl/ebcdic.h>
#endif

/* FIPS 180 */

static char *test[] = {
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    NULL,
}

static char *ret[] = {
    "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880",
    "d2516ee1acfa5baf33dfc1c471e438449ef134c8",
};

static char *bigret = "3232affa48628a26653b5aaa44541fd90d690603";

static char *pt(unsigned char *md);

int main(int argc, char *argv[])
{
    int i, err = 0;
    char **P, **R;
    static unsigned char buf[1000];
    char *p, *r;
    EVP_MD_CTX c;
    unsigned char md[SHA_DIGEST_LENGTH];

# ifdef CHARSET_EBCDIC
    ebcdic2ascii(test[0], test[0], strlen(test[0]));
    ebcdic2ascii(test[1], test[1], strlen(test[1]));
# endif

    EVP_MD_CTX_init(&c);
    P = test;
    R = ret;
    i = 1;
    while (*P != NULL) {
        EVP_Digest(*P, strlen((char *)*P), md, NULL, EVP_sha(), NULL);
        p = pt(md);
        if (strcmp(p, (char *)*R) != 0) {
            printf("error calculating SHA on '%s'\n", *P);
            printf("got %s instead of %s\n", p, *R);
            err++;
        } else
            printf("test %d ok\n", i);
        i++;
        R++;
        P++;
    }

    memset(buf, 'a', 1000);
# ifdef CHARSET_EBCDIC
    ebcdic2ascii(buf, buf, 1000);
# endif                         /* CHARSET_EBCDIC */
    EVP_DigestInit_ex(&c, EVP_sha(), NULL);
    for (i = 0; i < 1000; i++)
        EVP_DigestUpdate(&c, buf, 1000);
    EVP_DigestFinal_ex(&c, md, NULL);
    p = pt(md);

    r = bigret;
    if (strcmp(p, r) != 0) {
        printf("error calculating SHA on '%s'\n", p);
        printf("got %s instead of %s\n", p, r);
        err++;
    } else
        printf("test 3 ok\n");

# ifdef OPENSSL_SYS_NETWARE
    if (err)
        printf("ERROR: %d\n", err);
# endif
    EVP_MD_CTX_cleanup(&c);
    EXIT(err);
    return (0);
}

static char *pt(unsigned char *md)
{
    int i;
    static char buf[80];

    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(&(buf[i * 2]), "%02x", md[i]);
    return (buf);
}
#endif