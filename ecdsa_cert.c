#include "ecdsa_cert.h"


const char passwd[] = "123456";

session_t s;

int load_certificate_chain(const char *pemchain_path,
                            const char *keyfile_path,
                            session_t *s) {
    int err, i = 0;
    mbedtls_x509_crt crtchain;
    mbedtls_x509_crt* crt;
    mbedtls_x509_crt crt_SubCA2;
    mbedtls_pk_context pk;    //Public key container
    const char *pers = "ecdsa";
   
    mbedtls_pk_init(&pk);
    mbedtls_x509_crt_init(&crtchain);
    mbedtls_x509_crt_init(&crt_SubCA2);

    err = mbedtls_x509_crt_parse_file(&crtchain, pemchain_path);
    if (err != 0) {
        printf("load_cert: x509_crl_parse_file error\n");
        mbedtls_x509_crt_free(&crtchain);
        return -1;
    }

    size_t olen;
    unsigned char output_buf[4096];
    err = mbedtls_base64_encode(output_buf, 4096, &olen, crtchain.raw.p, crtchain.raw.len);   // equal = (cert1.raw.len == cert2.raw.len) && (memcmp(cert1.raw.p, cert2.raw.p, cert1.raw.len) == 0);
    if (err != 0) {
        mbedtls_strerror(err, output_buf, 4096);
        printf("load_cert, %s, %d\n", output_buf, crtchain.raw.len);
        return -1;
    }
    printf("load_cert cert. [leaf]\n");
    printf("------BEGIN CERTIFICATE-------\n");
    printf(" %s\n", output_buf);
    printf("------END CERTIFICATE---------\n");



    if (crtchain.raw.len > Certificate_BYTES_SIZE) { 
        printf("load_cert: certificate too big\n");
        return -1;
    }
    memcpy(&s->certificate.cert, crtchain.raw.p, crtchain.raw.len);
    s->certificate.cert_len = crtchain.raw.len;
    crt = &crtchain;
    while (crt->next != NULL) {
        if (i > Certificate_ARRAY_SIZE) {
            printf("load_cert: certificate chain too long (max 4 subcerts)\n");
            return -1;
        }
        crt = crt->next;
        if (crt->raw.len > Certificate_BYTES_SIZE) { 
            printf("load_cert: subcertificate too big (max 800bytes)\n");
            return -1;
        }
        memcpy(&s->certificate.sub_certs[i], crt->raw.p, crt->raw.len);
        s->certificate.subcert_len[i] = crt->raw.len;

        err = mbedtls_base64_encode(output_buf, 4096, &olen, s->certificate.sub_certs[i], s->certificate.subcert_len[i]);
        if (err != 0) {
            mbedtls_strerror(err, output_buf, 4096);
            printf("load_cert, %s, %d\n", output_buf, s->certificate.subcert_len[i]);
            return -1;
        }
        printf("SubCA_%s\n", i ? "1" : "2");
        printf("------BEGIN CERTIFICATE-------\n");
        printf(" %s\n", output_buf);
        printf("------END CERTIFICATE---------\n\n");

        i++;

    }
    
    err = mbedtls_x509_crt_parse(&crt_SubCA2, s->certificate.sub_certs[0], s->certificate.subcert_len[0]);  // SubCA2 Cert. parsing
    
    if (err != 0) {
        mbedtls_strerror(err, output_buf, 4096);
        printf("load_cert : failed parse SubCA2 cert ========================%s\n\n", output_buf);
        return -1;
    }

    // extract subCA2 public key from SubCA2 certificate
    err = mbedtls_ecdsa_from_keypair(&s->certificate.Sub2_key, mbedtls_pk_ec(crt_SubCA2.pk)); // setup an ECDSA context from an EC Key pair.  (Quick access to EC context inside a PK context.)

    if (err != 0) {
        mbedtls_strerror(err, output_buf, 4096);
        printf("load_cert, %s, \n", output_buf);
        return -1;
    }

    printf("load_cert : depth of cert tree, %d\n", i);
    mbedtls_x509_crt_free(&crtchain);
    err = mbedtls_pk_parse_keyfile(&pk, keyfile_path, passwd);    // Load and parse a private key
    if (err != 0) {
        printf("could not parse keyfile at %s\n",keyfile_path);
        return -1;
    }

    mbedtls_ecp_keypair *kp = mbedtls_pk_ec(pk);
    mbedtls_ecdsa_free(&s->certificate.key); // Free, if existing already

    err = mbedtls_ecdsa_from_keypair(&s->certificate.key, kp);    // ecdsa_context
    mbedtls_pk_free(&pk);
    if (err != 0) {
        printf("could not retrieve ecdsa from keypair at %s\n",keyfile_path);
        return -1;
    }

    printf("\nSeeding the random number generator...\n");
    mbedtls_entropy_init(&s->certificate.entropy);
    mbedtls_ctr_drbg_init(&s->certificate.ctr_drbg);
	if ((err = mbedtls_ctr_drbg_seed(&s->certificate.ctr_drbg, mbedtls_entropy_func,
                             &s->certificate.entropy,
                             (const unsigned char*)pers,
                             strlen(pers))) != 0) {
        printf("load_cert:  failed\n  ! ctr_drbg_init returned %d\n", err);
        return -1;
    } 

    mbedtls_x509_crt_free(&crtchain);
    mbedtls_x509_crt_free(&crt_SubCA2);

    return 0;
}


int main() {

    int err;

    unsigned char msg[] = "This should be hash to verify.";
    unsigned char digest[32];
    unsigned char sig[512];
    size_t sig_len;
    mbedtls_x509_crt leaf_crt;

    mbedtls_ecdsa_context leaf_pub_key;

    memset(digest, 0, sizeof(digest));
    memset(sig, 0, sizeof(sig));

    mbedtls_ecdsa_init(&leaf_pub_key);
    mbedtls_x509_crt_init(&leaf_crt);

    if (load_certificate_chain("certs/certchain.pem", "certs/leaf.key", &s) != 0) {  // parsing certchain and leaf private key
        printf("faile to load certificate\n");
        return -1;
    }

    printf(" ok (leaf private key size: %d bits)\n", (int) s.certificate.key.grp.pbits);
    printf(" ok (subCA2 public key size: %d bits)\n", (int) s.certificate.Sub2_key.grp.pbits);

    
    mbedtls_sha256(msg, sizeof(msg), digest, 0);                                // hash message
    
    err = mbedtls_ecdsa_write_signature(&s.certificate.key, MBEDTLS_MD_SHA256,  // sign with leaf private key
                                digest, 32,
                                sig,
                                &sig_len,
                                mbedtls_ctr_drbg_random,
                                &s.certificate.ctr_drbg); 
    if (err != 0) {
        printf("ecdsa write sig err\n");
        return -1;
    }

    err = mbedtls_x509_crt_parse(&leaf_crt, s.certificate.cert, s.certificate.cert_len);   // parsing leaf certificate
    if (err != 0) {
        printf("parsing leaf certificate err\n");
        return -1;
    }

    err = mbedtls_ecdsa_from_keypair(&leaf_pub_key, mbedtls_pk_ec(leaf_crt.pk));    // get ecdsa context type leaf public key from leaf certificate
    if (err != 0) {
        printf("get leaf public key err\n");
        return -1;
    }

    err = mbedtls_ecdsa_read_signature(&leaf_pub_key, digest, 32, sig, sig_len);   // verify signature with leaf public key
    if (err != 0) {
            printf("invalid signature\n");
            return -1;
    }

   
    return 0;




}

