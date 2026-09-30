/* On-target OpenSSL check, seeded as /usr/tests/openssl/openssl-smoke and run by
 * regress/openssl-syscall-smoke/run.sh. A dynamically linked PIE against libcrypto.so.3 and
 * libssl.so.3 (build.rs's `build_openssl_smoke`).
 *
 * Known answers for SHA-256 (FIPS 180-2 "abc"), AES-256-GCM (McGrew-Viega test case 14, which runs
 * the AES-NI/PCLMULQDQ assembly: a wrong AVX decision would fault here, since the kernel doesn't
 * enable AVX state) and MD4 (RFC 1320 "abc") through the legacy provider, which OpenSSL dlopen()s
 * from /usr/lib/ossl-modules/legacy.so. Then RAND_bytes, ECDSA P-256 and Ed25519 sign/verify, and a
 * TLS 1.3 handshake plus one message each way between a client and a server in this process,
 * connected by a BIO pair (no sockets: there's no loopback interface). Prints one line per check;
 * exit status is the number of failures. */
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void check(int ok, const char *what) {
    if (ok) {
        printf("openssl-smoke: ok: %s\n", what);
    } else {
        printf("openssl-smoke: FAIL: %s\n", what);
        ERR_print_errors_fp(stdout);
        failures++;
    }
}

static int hex_is(const unsigned char *bytes, size_t len, const char *hex) {
    char buf[2 * EVP_MAX_MD_SIZE + 1];
    if (len > EVP_MAX_MD_SIZE)
        return 0;
    for (size_t i = 0; i < len; i++)
        sprintf(buf + 2 * i, "%02x", bytes[i]);
    return strcmp(buf, hex) == 0;
}

static int digest_is(const char *alg, const char *msg, const char *hex) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD *md_alg = EVP_MD_fetch(NULL, alg, NULL);
    int ok = md_alg && EVP_Digest(msg, strlen(msg), md, &len, md_alg, NULL) &&
             hex_is(md, len, hex);
    EVP_MD_free(md_alg);
    return ok;
}

static int aes_256_gcm_kat(void) {
    static const unsigned char zero[32];
    unsigned char ct[16], tag[16];
    int len = 0, fin = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = ctx && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, zero, zero) &&
             EVP_EncryptUpdate(ctx, ct, &len, zero, 16) &&
             EVP_EncryptFinal_ex(ctx, ct + len, &fin) &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) &&
             hex_is(ct, 16, "cea7403d4d606b6e074ec5d3baf39d18") &&
             hex_is(tag, 16, "d0d1c8a799996bf0265b98b5d48ab919");
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int sign_verify(EVP_PKEY *key, const EVP_MD *md) {
    static const unsigned char msg[] = "OxideBSD";
    unsigned char sig[256];
    size_t siglen = sizeof sig;
    EVP_MD_CTX *sctx = EVP_MD_CTX_new(), *vctx = EVP_MD_CTX_new();
    int ok = key && sctx && vctx && EVP_DigestSignInit(sctx, NULL, md, NULL, key) &&
             EVP_DigestSign(sctx, sig, &siglen, msg, sizeof msg) &&
             EVP_DigestVerifyInit(vctx, NULL, md, NULL, key) &&
             EVP_DigestVerify(vctx, sig, siglen, msg, sizeof msg) == 1;
    /* A flipped bit must not verify. */
    sig[siglen / 2] ^= 1;
    ok = ok && EVP_DigestVerifyInit(vctx, NULL, md, NULL, key) &&
         EVP_DigestVerify(vctx, sig, siglen, msg, sizeof msg) != 1;
    EVP_MD_CTX_free(sctx);
    EVP_MD_CTX_free(vctx);
    return ok;
}

/* A self-signed certificate for "localhost", valid from now for a day. */
static X509 *self_signed(EVP_PKEY *key) {
    X509 *cert = X509_new();
    X509_NAME *name = X509_NAME_new();
    int ok = cert && name && X509_set_version(cert, X509_VERSION_3) &&
             ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) &&
             X509_gmtime_adj(X509_getm_notBefore(cert), -60) &&
             X509_gmtime_adj(X509_getm_notAfter(cert), 86400) &&
             X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                        (const unsigned char *)"localhost", -1, -1, 0) &&
             X509_set_subject_name(cert, name) && X509_set_issuer_name(cert, name) &&
             X509_set_pubkey(cert, key) && X509_sign(cert, key, EVP_sha256()) > 0;
    X509_NAME_free(name);
    if (!ok) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

static int want_more(SSL *ssl, int rc) {
    int err = SSL_get_error(ssl, rc);
    return err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE;
}

static int tls13_bio_pair(void) {
    EVP_PKEY *key = EVP_EC_gen("P-256");
    X509 *cert = key ? self_signed(key) : NULL;
    SSL_CTX *sctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
    SSL *server = NULL, *client = NULL;
    BIO *sbio = NULL, *cbio = NULL;
    char buf[16];
    int ok = cert && sctx && cctx && SSL_CTX_use_certificate(sctx, cert) &&
             SSL_CTX_use_PrivateKey(sctx, key) &&
             SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION) &&
             X509_STORE_add_cert(SSL_CTX_get_cert_store(cctx), cert);
    if (ok) {
        SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);
        server = SSL_new(sctx);
        client = SSL_new(cctx);
        ok = server && client && BIO_new_bio_pair(&sbio, 0, &cbio, 0) &&
             SSL_set1_host(client, "localhost") &&
             SSL_set_tlsext_host_name(client, "localhost");
    }
    if (ok) {
        SSL_set_bio(server, sbio, sbio);
        SSL_set_bio(client, cbio, cbio);
        SSL_set_accept_state(server);
        SSL_set_connect_state(client);
        int cdone = 0, sdone = 0;
        for (int i = 0; ok && !(cdone && sdone) && i < 100; i++) {
            if (!cdone) {
                int rc = SSL_do_handshake(client);
                cdone = rc == 1;
                ok = cdone || want_more(client, rc);
            }
            if (ok && !sdone) {
                int rc = SSL_do_handshake(server);
                sdone = rc == 1;
                ok = sdone || want_more(server, rc);
            }
        }
        ok = ok && cdone && sdone && SSL_version(client) == TLS1_3_VERSION &&
             SSL_get_verify_result(client) == X509_V_OK;
        if (ok)
            printf("openssl-smoke: handshake: %s, %s\n", SSL_get_version(client),
                   SSL_get_cipher_name(client));
    }
    ok = ok && SSL_write(client, "ping", 4) == 4 && SSL_read(server, buf, sizeof buf) == 4 &&
         memcmp(buf, "ping", 4) == 0 && SSL_write(server, "pong", 4) == 4 &&
         SSL_read(client, buf, sizeof buf) == 4 && memcmp(buf, "pong", 4) == 0;
    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    X509_free(cert);
    EVP_PKEY_free(key);
    return ok;
}

int main(void) {
    printf("openssl-smoke: %s\n", OpenSSL_version(OPENSSL_VERSION));

    check(digest_is("SHA256", "abc",
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
          "SHA-256 known answer");
    check(aes_256_gcm_kat(), "AES-256-GCM known answer");

    /* Loading any provider by hand stops the default one loading implicitly: load both. */
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    check(legacy != NULL, "legacy provider module loads");
    check(deflt != NULL, "default provider loads");
    check(legacy && digest_is("MD4", "abc", "a448017aaf21d8525fc10ae87aa6729d"),
          "MD4 known answer (legacy provider)");

    unsigned char r1[32] = {0}, r2[32] = {0}, zero[32] = {0};
    check(RAND_bytes(r1, sizeof r1) == 1 && RAND_bytes(r2, sizeof r2) == 1 &&
              memcmp(r1, zero, sizeof r1) != 0 && memcmp(r1, r2, sizeof r1) != 0,
          "RAND_bytes");

    EVP_PKEY *ec = EVP_EC_gen("P-256");
    check(sign_verify(ec, EVP_sha256()), "ECDSA P-256 sign/verify");
    EVP_PKEY_free(ec);
    EVP_PKEY *ed = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    check(sign_verify(ed, NULL), "Ed25519 sign/verify");
    EVP_PKEY_free(ed);

    check(tls13_bio_pair(), "TLS 1.3 handshake and data over a BIO pair");

    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(deflt);
    return failures;
}
