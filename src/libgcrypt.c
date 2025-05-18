/* Copyright (C) Simon Josefsson
 * Copyright (C) The Written Word, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"

#ifdef LIBSSH2_LIBGCRYPT

int _libssh2_hmac_ctx_init(libssh2_hmac_ctx *ctx)
{
    *ctx = NULL;
    return 1;
}

#if LIBSSH2_MD5
int _libssh2_hmac_md5_init(libssh2_hmac_ctx *ctx,
                           void *key, size_t keylen)
{
    gcry_error_t err;
    err = gcry_md_open(ctx, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    err = gcry_md_setkey(*ctx, key, keylen);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    return 1;
}
#endif

#if LIBSSH2_HMAC_RIPEMD
int _libssh2_hmac_ripemd160_init(libssh2_hmac_ctx *ctx,
                                 void *key, size_t keylen)
{
    gcry_error_t err;
    err = gcry_md_open(ctx, GCRY_MD_RMD160, GCRY_MD_FLAG_HMAC);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    err = gcry_md_setkey(*ctx, key, keylen);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    return 1;
}
#endif

int _libssh2_hmac_sha1_init(libssh2_hmac_ctx *ctx,
                            void *key, size_t keylen)
{
    gcry_error_t err;
    err = gcry_md_open(ctx, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    err = gcry_md_setkey(*ctx, key, keylen);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    return 1;
}

int _libssh2_hmac_sha256_init(libssh2_hmac_ctx *ctx,
                              void *key, size_t keylen)
{
    gcry_error_t err;
    err = gcry_md_open(ctx, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    err = gcry_md_setkey(*ctx, key, keylen);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    return 1;
}

int _libssh2_hmac_sha512_init(libssh2_hmac_ctx *ctx,
                              void *key, size_t keylen)
{
    gcry_error_t err;
    err = gcry_md_open(ctx, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    err = gcry_md_setkey(*ctx, key, keylen);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    return 1;
}

int _libssh2_hmac_update(libssh2_hmac_ctx *ctx,
                         const void *data, size_t datalen)
{
    gcry_md_write(*ctx, data, datalen);
    return 1;
}

int _libssh2_hmac_final(libssh2_hmac_ctx *ctx, void *data)
{
    unsigned char *res = gcry_md_read(*ctx, 0);

    if(!res)
        return 0;

    memcpy(data, res, gcry_md_get_algo_dlen(gcry_md_get_algo(*ctx)));

    return 1;
}

void _libssh2_hmac_cleanup(libssh2_hmac_ctx *ctx)
{
    gcry_md_close(*ctx);
}

#if LIBSSH2_RSA
int
_libssh2_rsa_new(libssh2_rsa_ctx ** rsa,
                 const unsigned char *edata,
                 unsigned long elen,
                 const unsigned char *ndata,
                 unsigned long nlen,
                 const unsigned char *ddata,
                 unsigned long dlen,
                 const unsigned char *pdata,
                 unsigned long plen,
                 const unsigned char *qdata,
                 unsigned long qlen,
                 const unsigned char *e1data,
                 unsigned long e1len,
                 const unsigned char *e2data,
                 unsigned long e2len,
                 const unsigned char *coeffdata, unsigned long coefflen)
{
    int rc;

    (void)e1data;
    (void)e1len;
    (void)e2data;
    (void)e2len;

    if(ddata) {
        rc = gcry_sexp_build(rsa, NULL,
                 "(private-key(rsa(n%b)(e%b)(d%b)(q%b)(p%b)(u%b)))",
                 nlen, ndata, elen, edata, dlen, ddata, plen, pdata,
                 qlen, qdata, coefflen, coeffdata);
    }
    else {
        rc = gcry_sexp_build(rsa, NULL, "(public-key(rsa(n%b)(e%b)))",
                             nlen, ndata, elen, edata);
    }
    if(rc) {
        *rsa = NULL;
        return -1;
    }

    return 0;
}

#if LIBSSH2_RSA_SHA1
int
_libssh2_rsa_sha1_verify(libssh2_rsa_ctx * rsa,
                         const unsigned char *sig,
                         size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    gcry_sexp_t s_sig, s_hash;
    int rc = -1;

    if(libssh2_sha1(m, m_len, hash)) {
        return -1;
    }

    rc = gcry_sexp_build(&s_hash, NULL,
                         "(data (flags pkcs1) (hash sha1 %b))",
                         SHA_DIGEST_LENGTH, hash);
    if(rc) {
        return -1;
    }

    rc = gcry_sexp_build(&s_sig, NULL, "(sig-val(rsa(s %b)))", sig_len, sig);
    if(rc) {
        gcry_sexp_release(s_hash);
        return -1;
    }

    rc = gcry_pk_verify(s_sig, s_hash, rsa);
    gcry_sexp_release(s_sig);
    gcry_sexp_release(s_hash);

    return (rc == 0) ? 0 : -1;
}
#endif
#endif

#if LIBSSH2_DSA
int
_libssh2_dsa_new(libssh2_dsa_ctx ** dsactx,
                 const unsigned char *p,
                 unsigned long p_len,
                 const unsigned char *q,
                 unsigned long q_len,
                 const unsigned char *g,
                 unsigned long g_len,
                 const unsigned char *y,
                 unsigned long y_len,
                 const unsigned char *x, unsigned long x_len)
{
    int rc;

    if(x_len) {
        rc = gcry_sexp_build(dsactx, NULL,
                 "(private-key(dsa(p%b)(q%b)(g%b)(y%b)(x%b)))",
                  p_len, p, q_len, q, g_len, g, y_len, y, x_len, x);
    }
    else {
        rc = gcry_sexp_build(dsactx, NULL,
                             "(public-key(dsa(p%b)(q%b)(g%b)(y%b)))",
                             p_len, p, q_len, q, g_len, g, y_len, y);
    }

    if(rc) {
        *dsactx = NULL;
        return -1;
    }

    return 0;
}
#endif

#if LIBSSH2_RSA
int
_libssh2_rsa_new_private_frommemory(libssh2_rsa_ctx ** rsa,
                                    LIBSSH2_SESSION * session,
                                    const char *filedata, size_t filedata_len,
                                    const unsigned char *passphrase)
{
    (void)rsa;
    (void)filedata;
    (void)filedata_len;
    (void)passphrase;

    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                          "Unable to extract private key from memory: "
                          "Method unimplemented in libgcrypt backend");
}

int
_libssh2_rsa_new_private(libssh2_rsa_ctx ** rsa,
                         LIBSSH2_SESSION * session,
                         const char *filename, const unsigned char *passphrase)
{
    FILE *fp;
    unsigned char *data, *save_data;
    size_t datalen;
    int ret;
    unsigned char *n, *e, *d, *p, *q, *e1, *e2, *coeff;
    unsigned int nlen, elen, dlen, plen, qlen, e1len, e2len, coefflen;

    fp = fopen(filename, FOPEN_READTEXT);
    if(!fp) {
        return -1;
    }

    ret = _libssh2_pem_parse(session,
                             "-----BEGIN RSA PRIVATE KEY-----",
                             "-----END RSA PRIVATE KEY-----",
                             passphrase,
                             fp, &data, &datalen);
    fclose(fp);
    if(ret) {
        return -1;
    }

    save_data = data;

    if(_libssh2_pem_decode_sequence(&data, &datalen)) {
        ret = -1;
        goto fail;
    }

    /* First read Version field (should be 0). */
    ret = _libssh2_pem_decode_integer(&data, &datalen, &n, &nlen);
    if(ret || (nlen != 1 && *n != '\0')) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &n, &nlen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &e, &elen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &d, &dlen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &p, &plen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &q, &qlen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &e1, &e1len);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &e2, &e2len);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &coeff, &coefflen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    if(_libssh2_rsa_new(rsa, e, elen, n, nlen, d, dlen, p, plen,
                        q, qlen, e1, e1len, e2, e2len, coeff, coefflen)) {
        ret = -1;
        goto fail;
    }

    ret = 0;

fail:
    LIBSSH2_FREE(session, save_data);
    return ret;
}
#endif

#if LIBSSH2_DSA
int
_libssh2_dsa_new_private_frommemory(libssh2_dsa_ctx ** dsa,
                                    LIBSSH2_SESSION * session,
                                    const char *filedata, size_t filedata_len,
                                    const unsigned char *passphrase)
{
    (void)dsa;
    (void)filedata;
    (void)filedata_len;
    (void)passphrase;

    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                          "Unable to extract private key from memory: "
                          "Method unimplemented in libgcrypt backend");
}

int
_libssh2_dsa_new_private(libssh2_dsa_ctx ** dsa,
                         LIBSSH2_SESSION * session,
                         const char *filename, const unsigned char *passphrase)
{
    FILE *fp;
    unsigned char *data, *save_data;
    size_t datalen;
    int ret;
    unsigned char *p, *q, *g, *y, *x;
    unsigned int plen, qlen, glen, ylen, xlen;

    fp = fopen(filename, FOPEN_READTEXT);
    if(!fp) {
        return -1;
    }

    ret = _libssh2_pem_parse(session,
                             "-----BEGIN DSA PRIVATE KEY-----",
                             "-----END DSA PRIVATE KEY-----",
                             passphrase,
                             fp, &data, &datalen);
    fclose(fp);
    if(ret) {
        return -1;
    }

    save_data = data;

    if(_libssh2_pem_decode_sequence(&data, &datalen)) {
        ret = -1;
        goto fail;
    }

    /* First read Version field (should be 0). */
    ret = _libssh2_pem_decode_integer(&data, &datalen, &p, &plen);
    if(ret || (plen != 1 && *p != '\0')) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &p, &plen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &q, &qlen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &g, &glen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &y, &ylen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = _libssh2_pem_decode_integer(&data, &datalen, &x, &xlen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    if(datalen) {
        ret = -1;
        goto fail;
    }

    if(_libssh2_dsa_new(dsa, p, plen, q, qlen, g, glen, y, ylen, x, xlen)) {
        ret = -1;
        goto fail;
    }

    ret = 0;

fail:
    LIBSSH2_FREE(session, save_data);
    return ret;
}
#endif

#if LIBSSH2_ED25519
int
_libssh2_curve25519_new(LIBSSH2_SESSION *session, uint8_t **out_public_key,
                        uint8_t **out_private_key)
{
    unsigned char *priv = NULL;
    unsigned char pub[LIBSSH2_ED25519_KEY_LEN];
    unsigned char *sess_priv = NULL;
    unsigned char *sess_pub = NULL;

    if(gcry_ecc_get_algo_keylen(GCRY_ECC_CURVE25519) != LIBSSH2_ED25519_KEY_LEN)
        return -1;

    /* We want out_private_key to be the 32 random bytes pre-scalar-decoding.
     * Thus, we do not use gcry_pk_genkey with an s-expression like
     * (genkey(ecc(curve Curve25519)(flags djb-tweak))) since the generated
     * private key (d) will already be the decoded scalar (from which there is
     * no way to recover the originally generated bits). */

    priv = gcry_random_bytes_secure(LIBSSH2_ED25519_KEY_LEN,
                                    GCRY_VERY_STRONG_RANDOM);
    if(!priv)
        return -1;

    if(gcry_ecc_mul_point(GCRY_ECC_CURVE25519, pub, priv, NULL))
        goto fail;

    if(out_private_key) {
        sess_priv = LIBSSH2_ALLOC(session, LIBSSH2_ED25519_KEY_LEN);
        if(!sess_priv)
            goto fail;
        memcpy(sess_priv, priv, LIBSSH2_ED25519_KEY_LEN);
    }

    if(out_public_key) {
        sess_pub = LIBSSH2_ALLOC(session, LIBSSH2_ED25519_KEY_LEN);
        if(!sess_pub)
            goto fail;
        memcpy(sess_pub, pub, LIBSSH2_ED25519_KEY_LEN);
    }

    if(sess_priv)
        *out_private_key = sess_priv;
    if(sess_pub)
        *out_public_key = sess_pub;
    gcry_free(priv);
    return 0;

fail:
    if(sess_pub)
        LIBSSH2_FREE(session, sess_pub);
    if(sess_priv)
        LIBSSH2_FREE(session, sess_priv);
    if(priv)
        gcry_free(priv);
    return -1;
}

static const unsigned char pk_ed25519_der[] = {
    0x30, 0x05, 0x06, 0x03, /* seq { oid */
    40 * 1 + 3, 101, 112, /* { id-ed25519: 1.3.101.112 }} */
    0x04, LIBSSH2_ED25519_KEY_LEN + 2, /* PrivateKey */
    0x04, LIBSSH2_ED25519_KEY_LEN /* { CurvePrivateKey } */
};

int
_libssh2_ed25519_new_private(libssh2_ed25519_ctx **ed_ctx,
                            LIBSSH2_SESSION *session,
                            const char *filename, const uint8_t *passphrase)
{
    FILE *fp;
    int ret;
    unsigned char *data, *save_data;
    size_t datalen;
    unsigned char *version;
    unsigned int version_len;
    gcry_sexp_t s_key;

    if(!session) {
        _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                       "Session is required");
        return -1;
    }

    if(passphrase && *passphrase) {
        return _libssh2_error(
            session,
            LIBSSH2_ERROR_INVAL,
            "Passphrase-protected ED25519 private key files are unsupported");
    }

    _libssh2_init_if_needed();

    fp = fopen(filename, FOPEN_READTEXT);
    if(!fp) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                       "Unable to open ED25519 private key file");
        return -1;
    }

    ret = _libssh2_pem_parse(session,
                             "-----BEGIN PRIVATE KEY-----",
                             "-----END PRIVATE KEY-----",
                             passphrase,
                             fp, &data, &datalen);
    fclose(fp);
    if(ret)
        return -1;

    save_data = data;

    if(_libssh2_pem_decode_sequence(&data, &datalen))
        goto fail;

    if(_libssh2_pem_decode_integer(&data, &datalen, &version, &version_len) ||
       version_len != 1 || (*version != 0 && *version != 1))
        goto fail;

    if(datalen < sizeof(pk_ed25519_der) ||
       memcmp(data, pk_ed25519_der, sizeof(pk_ed25519_der)))
        goto fail;
    data += sizeof(pk_ed25519_der);
    datalen -= sizeof(pk_ed25519_der);

    if(datalen < LIBSSH2_ED25519_KEY_LEN)
        goto fail;

    if(gcry_sexp_build(&s_key, NULL,
                       "(private-key(ecc(curve Ed25519)(flags eddsa)(d %b)))",
                       LIBSSH2_ED25519_KEY_LEN, data))
        goto fail;

    *ed_ctx = s_key;
    LIBSSH2_FREE(session, save_data);
    return 0;

fail:
    LIBSSH2_FREE(session, save_data);
    return -1;
}

int
_libssh2_ed25519_new_public(libssh2_ed25519_ctx **ed_ctx,
                            LIBSSH2_SESSION *session,
                            const unsigned char *raw_pub_key,
                            const size_t key_len)
{
    gcry_sexp_t s_key;
    if(!ed_ctx)
        return -1;
    if(gcry_sexp_build(&s_key, NULL,
                       "(public-key(ecc(curve Ed25519)(flags eddsa)(q %b)))",
                       key_len, raw_pub_key))
        return _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                              "could not create ED25519 public key");
    *ed_ctx = s_key;
    return 0;
}


int
_libssh2_ed25519_new_private_frommemory(libssh2_ed25519_ctx **ed_ctx,
                                        LIBSSH2_SESSION *session,
                                        const char *filedata,
                                        size_t filedata_len,
                                        const unsigned char *passphrase)
{
    (void)ed_ctx;
    (void)filedata;
    (void)filedata_len;
    (void)passphrase;

    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                          "Unable to extract private key from memory: "
                          "Method unimplemented in libgcrypt backend");
}
#endif

#if LIBSSH2_RSA
#if LIBSSH2_RSA_SHA1
int
_libssh2_rsa_sha1_sign(LIBSSH2_SESSION * session,
                       libssh2_rsa_ctx * rsactx,
                       const unsigned char *hash,
                       size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    gcry_sexp_t sig_sexp;
    gcry_sexp_t data;
    int rc;
    const char *tmp;
    size_t size;

    if(hash_len != SHA_DIGEST_LENGTH) {
        return -1;
    }

    if(gcry_sexp_build(&data, NULL,
                       "(data (flags pkcs1) (hash sha1 %b))",
                       hash_len, hash)) {
        return -1;
    }

    rc = gcry_pk_sign(&sig_sexp, data, rsactx);

    gcry_sexp_release(data);

    if(rc) {
        return -1;
    }

    data = gcry_sexp_find_token(sig_sexp, "s", 0);
    if(!data) {
        return -1;
    }

    tmp = gcry_sexp_nth_data(data, 1, &size);
    if(!tmp) {
        gcry_sexp_release(data);
        return -1;
    }

    if(tmp[0] == '\0') {
        tmp++;
        size--;
    }

    *signature = LIBSSH2_ALLOC(session, size);
    if(!*signature) {
        gcry_sexp_release(data);
        return -1;
    }
    memcpy(*signature, tmp, size);
    *signature_len = size;

    gcry_sexp_release(data);

    return rc;
}
#endif
#endif

#if LIBSSH2_DSA
int
_libssh2_dsa_sha1_sign(libssh2_dsa_ctx * dsactx,
                       const unsigned char *hash,
                       size_t hash_len, unsigned char *sig)
{
    unsigned char zhash[SHA_DIGEST_LENGTH + 1];
    gcry_sexp_t sig_sexp;
    gcry_sexp_t data;
    int ret;
    const char *tmp;
    size_t size;

    if(hash_len != SHA_DIGEST_LENGTH) {
        return -1;
    }

    memcpy(zhash + 1, hash, hash_len);
    zhash[0] = 0;

    if(gcry_sexp_build(&data, NULL, "(data (value %b))",
                       (int)(hash_len + 1), zhash)) {
        return -1;
    }

    ret = gcry_pk_sign(&sig_sexp, data, dsactx);

    gcry_sexp_release(data);

    if(ret) {
        return -1;
    }

    memset(sig, 0, 40);

    /* Extract R. */

    data = gcry_sexp_find_token(sig_sexp, "r", 0);
    if(!data)
        goto err;

    tmp = gcry_sexp_nth_data(data, 1, &size);
    if(!tmp)
        goto err;

    if(tmp[0] == '\0') {
        tmp++;
        size--;
    }

    if(size < 1 || size > 20)
        goto err;

    memcpy(sig + (20 - size), tmp, size);

    gcry_sexp_release(data);

    /* Extract S. */

    data = gcry_sexp_find_token(sig_sexp, "s", 0);
    if(!data)
        goto err;

    tmp = gcry_sexp_nth_data(data, 1, &size);
    if(!tmp)
        goto err;

    if(tmp[0] == '\0') {
        tmp++;
        size--;
    }

    if(size < 1 || size > 20)
        goto err;

    memcpy(sig + 20 + (20 - size), tmp, size);
    goto out;

err:
    ret = -1;

out:
    if(sig_sexp) {
        gcry_sexp_release(sig_sexp);
    }
    if(data) {
        gcry_sexp_release(data);
    }
    return ret;
}

int
_libssh2_dsa_sha1_verify(libssh2_dsa_ctx * dsactx,
                         const unsigned char *sig,
                         const unsigned char *m, size_t m_len)
{
    unsigned char hash[SHA_DIGEST_LENGTH + 1];
    gcry_sexp_t s_sig, s_hash;
    int rc = -1;

    if(libssh2_sha1(m, m_len, hash + 1)) {
        return -1;
    }
    hash[0] = 0;

    if(gcry_sexp_build(&s_hash, NULL, "(data(flags raw)(value %b))",
                       SHA_DIGEST_LENGTH + 1, hash)) {
        return -1;
    }

    if(gcry_sexp_build(&s_sig, NULL, "(sig-val(dsa(r %b)(s %b)))",
                       20, sig, 20, sig + 20)) {
        gcry_sexp_release(s_hash);
        return -1;
    }

    rc = gcry_pk_verify(s_sig, s_hash, dsactx);
    gcry_sexp_release(s_sig);
    gcry_sexp_release(s_hash);

    return (rc == 0) ? 0 : -1;
}
#endif

#if LIBSSH2_ED25519
int
_libssh2_ed25519_sign(libssh2_ed25519_ctx *ctx, LIBSSH2_SESSION *session,
                      uint8_t **out_sig, size_t *out_sig_len,
                      const uint8_t *message, size_t message_len)
{
    gcry_sexp_t s_data = NULL;
    gcry_error_t err;
    gcry_sexp_t s_sig = NULL;
    gcry_mpi_t r = NULL, s = NULL;
    unsigned int rlen = 0, slen = 0;
    const unsigned char *rbuf = NULL, *sbuf = NULL;
    unsigned char *sig = NULL;

    if(gcry_sexp_build(&s_data, NULL,
                       "(data(flags eddsa)(hash-algo sha512)(value %b))",
                       message_len, message))
        return -1;

    err = gcry_pk_sign(&s_sig, s_data, ctx);
    gcry_sexp_release(s_data);
    if(err)
        return -1;

    err = gcry_sexp_extract_param(s_sig, "sig-val", "/rs", &r, &s, NULL);
    gcry_sexp_release(s_sig);
    if(err)
        return -1;

    rbuf = gcry_mpi_get_opaque(r, &rlen);
    sbuf = gcry_mpi_get_opaque(s, &slen);
    if(!r || !s)
        goto fail;

    rlen = (rlen + 7) / 8;
    slen = (slen + 7) / 8;
    if(rlen + slen != LIBSSH2_ED25519_SIG_LEN)
        goto fail;

    sig = LIBSSH2_ALLOC(session, LIBSSH2_ED25519_SIG_LEN);
    if(!sig)
        goto fail;

    memcpy(sig, rbuf, rlen);
    memcpy(sig + rlen, sbuf, slen);

    *out_sig = sig;
    *out_sig_len = LIBSSH2_ED25519_SIG_LEN;

    gcry_mpi_release(r);
    gcry_mpi_release(s);
    return 0;

fail:
    gcry_mpi_release(r);
    gcry_mpi_release(s);
    return -1;
}

int
_libssh2_curve25519_gen_k(_libssh2_bn **k,
                          uint8_t private_key[LIBSSH2_ED25519_KEY_LEN],
                          uint8_t server_public_key[LIBSSH2_ED25519_KEY_LEN])
{
    unsigned char k_raw[LIBSSH2_ED25519_KEY_LEN];

    if(!k || *k ||
       gcry_ecc_get_algo_keylen(GCRY_ECC_CURVE25519) != LIBSSH2_ED25519_KEY_LEN)
        return -1;

    if(gcry_ecc_mul_point(GCRY_ECC_CURVE25519, k_raw,
                          private_key, server_public_key))
        return -1;

    if(gcry_mpi_scan(k, GCRYMPI_FMT_USG, k_raw, sizeof(k_raw), NULL))
        return -1;

    return 0;
}

int
_libssh2_ed25519_verify(libssh2_ed25519_ctx *ctx, const uint8_t *s,
                        size_t s_len, const uint8_t *m, size_t m_len)
{
    gcry_sexp_t s_data;
    gcry_sexp_t s_sig;
    int ret;

    if(s_len != LIBSSH2_ED25519_SIG_LEN)
        return -1;

    if(gcry_sexp_build(&s_data, NULL,
                       "(data(flags eddsa)(hash-algo sha512)(value %b))",
                       m_len, m))
        return -1;

    if(gcry_sexp_build(&s_sig, NULL,
                       "(sig-val(eddsa (r %b)(s %b)))",
                       LIBSSH2_ED25519_SIG_LEN / 2,
                       s,
                       LIBSSH2_ED25519_SIG_LEN / 2,
                       s + LIBSSH2_ED25519_SIG_LEN / 2)) {
        gcry_sexp_release(s_data);
        return -1;
    }

    ret = gcry_pk_verify(s_sig, s_data, ctx) ? -1 : 0;

    gcry_sexp_release(s_sig);
    gcry_sexp_release(s_data);

    return ret;
}
#endif

int
_libssh2_cipher_init(_libssh2_cipher_ctx * h,
                     _libssh2_cipher_type(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
    int ret;
    int cipher = _libssh2_gcry_cipher(algo);
    int mode = _libssh2_gcry_mode(algo);
    size_t keylen = gcry_cipher_get_algo_keylen(cipher);

    (void)encrypt;

    ret = gcry_cipher_open(h, cipher, mode, 0);
    if(ret) {
        return -1;
    }

    ret = gcry_cipher_setkey(*h, secret, keylen);
    if(ret) {
        gcry_cipher_close(*h);
        return -1;
    }

    if(mode != GCRY_CIPHER_MODE_STREAM) {
        size_t blklen = gcry_cipher_get_algo_blklen(cipher);
        if(mode == GCRY_CIPHER_MODE_CTR)
            ret = gcry_cipher_setctr(*h, iv, blklen);
        else
            ret = gcry_cipher_setiv(*h, iv, blklen);
        if(ret) {
            gcry_cipher_close(*h);
            return -1;
        }
    }

    return 0;
}

int
_libssh2_cipher_crypt(_libssh2_cipher_ctx * ctx,
                      _libssh2_cipher_type(algo),
                      int encrypt, unsigned char *block, size_t blklen,
                      int firstlast)
{
    int ret;

    (void)algo;
    (void)firstlast;

    if(encrypt) {
        ret = gcry_cipher_encrypt(*ctx, block, blklen, block, blklen);
    }
    else {
        ret = gcry_cipher_decrypt(*ctx, block, blklen, block, blklen);
    }
    return ret;
}

int
_libssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                unsigned char **method,
                                size_t *method_len,
                                unsigned char **pubkeydata,
                                size_t *pubkeydata_len,
                                const char *privatekeydata,
                                size_t privatekeydata_len,
                                const char *passphrase)
{
    (void)method;
    (void)method_len;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)privatekeydata;
    (void)privatekeydata_len;
    (void)passphrase;

    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                          "Unable to extract public key from private "
                          "key in memory: "
                          "Method unimplemented in libgcrypt backend");
}

int
_libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                          unsigned char **method,
                          size_t *method_len,
                          unsigned char **pubkeydata,
                          size_t *pubkeydata_len,
                          const char *privatekey,
                          const char *passphrase)
{
    (void)method;
    (void)method_len;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)privatekey;
    (void)passphrase;

    return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                    "Unable to extract public key from private key file: "
                    "Method unimplemented in libgcrypt backend");
}

int
_libssh2_sk_pub_keyfilememory(LIBSSH2_SESSION *session,
                              unsigned char **method,
                              size_t *method_len,
                              unsigned char **pubkeydata,
                              size_t *pubkeydata_len,
                              int *algorithm,
                              unsigned char *flags,
                              const char **application,
                              const unsigned char **key_handle,
                              size_t *handle_len,
                              const char *privatekeydata,
                              size_t privatekeydata_len,
                              const char *passphrase)
{
    (void)method;
    (void)method_len;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)algorithm;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)handle_len;
    (void)privatekeydata;
    (void)privatekeydata_len;
    (void)passphrase;

    return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                    "Unable to extract public SK key from private key file: "
                    "Method unimplemented in libgcrypt backend");
}

void _libssh2_init_aes_ctr(void)
{
    /* no implementation */
}

void
_libssh2_dh_init(_libssh2_dh_ctx *dhctx)
{
    *dhctx = gcry_mpi_new(0);                   /* Random from client */
}

int
_libssh2_dh_key_pair(_libssh2_dh_ctx *dhctx, _libssh2_bn *public,
                     _libssh2_bn *g, _libssh2_bn *p, int group_order)
{
    /* Generate x and e */
    gcry_mpi_randomize(*dhctx, group_order * 8 - 1, GCRY_WEAK_RANDOM);
    gcry_mpi_powm(public, g, *dhctx, p);
    return 0;
}

int
_libssh2_dh_secret(_libssh2_dh_ctx *dhctx, _libssh2_bn *secret,
                   _libssh2_bn *f, _libssh2_bn *p)
{
    /* Compute the shared secret */
    gcry_mpi_powm(secret, f, *dhctx, p);
    return 0;
}

void
_libssh2_dh_dtor(_libssh2_dh_ctx *dhctx)
{
    gcry_mpi_release(*dhctx);
    *dhctx = NULL;
}

/* _libssh2_supported_key_sign_algorithms
 *
 * Return supported key hash algo upgrades, see crypto.h
 *
 */

const char *
_libssh2_supported_key_sign_algorithms(LIBSSH2_SESSION *session,
                                       unsigned char *key_method,
                                       size_t key_method_len)
{
    (void)session;
    (void)key_method;
    (void)key_method_len;

    return NULL;
}

#endif /* LIBSSH2_LIBGCRYPT */
