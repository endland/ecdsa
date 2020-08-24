#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <fcntl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h> 
#include <mbedtls/ecdh.h>  
#include <mbedtls/asn1write.h>
#include <time.h>

#define Certificate_BYTES_SIZE 800
#define Certificate_ARRAY_SIZE 4

const char passwd[] = '123456';

typedef struct session session_t;
struct session{
    uint64_t id;
  
    struct{
        uint8_t cert[Certificate_BYTES_SIZE]; 
        size_t cert_len;
        uint8_t sub_certs[Certificate_ARRAY_SIZE][Certificate_BYTES_SIZE]; 
        size_t subcert_len[Certificate_ARRAY_SIZE]; 
        mbedtls_ecdsa_context key;
        mbedtls_ecdsa_context Sub2_key;  
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
    } cert;
};

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
    memcpy(&s->cert.cert, crtchain.raw.p, crtchain.raw.len);
    s->cert.cert_len = crtchain.raw.len;
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
        memcpy(&s->cert.sub_certs[i], crt->raw.p, crt->raw.len);
        s->cert.subcert_len[i] = crt->raw.len;

        err = mbedtls_base64_encode(output_buf, 4096, &olen, s->cert.sub_certs[i], s->cert.subcert_len[i]);
        if (err != 0) {
            mbedtls_strerror(err, output_buf, 4096);
            printf("load_cert, %s, %d\n", output_buf, s->cert.subcert_len[i]);
            return -1;
        }
        printf("SubCA_%s\n", i ? "1" : "2");
        printf("------BEGIN CERTIFICATE-------\n");
        printf(" %s\n", output_buf);
        printf("------END CERTIFICATE---------\n\n");

        i++;

    }
    
    err = mbedtls_x509_crt_parse(&crt_SubCA2, s->cert.sub_certs[0], s->cert.subcert_len[0]);  // SubCA2 Cert. parsing
    
    if (err != 0) {
        mbedtls_strerror(err, output_buf, 4096);
        printf("load_cert : failed parse SubCA2 cert ========================%s\n\n", output_buf);
        return -1;
    }

    err = mbedtls_ecdsa_from_keypair(&s->cert.Sub2_key, mbedtls_pk_ec(crt_SubCA2.pk)); // setup an ECDSA context from an EC Key pair.  (Quick access to EC context inside a PK context.)

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
    mbedtls_ecdsa_free(&s->cert.key); // Free, if existing already
    err = mbedtls_ecdsa_from_keypair(&s->cert.key, kp);
    mbedtls_pk_free(&pk);
    if (err != 0) {
        printf("could not retrieve ecdsa from keypair at %s\n",keyfile_path);
        return -1;
    }

    mbedtls_entropy_init(&s->cert.entropy);
 
    mbedtls_ctr_drbg_init(&s->cert.ctr_drbg); // Added by JJS (2019.02.02)
	if ((err = mbedtls_ctr_drbg_seed(&s->cert.ctr_drbg, mbedtls_entropy_func,
                             &s->cert.entropy,
                             (const unsigned char*)pers,
                             strlen(pers))) != 0) {
        printf("load_cert:  failed\n  ! ctr_drbg_init returned %d\n", err);
        return -1;
    } 

    mbedtls_x509_crt_free(&crtchain);
    mbedtls_x509_crt_free(&crt_moSubCA2);
    return 0;
}


int main() {

    struct session_t s;

    if (load_certificate_chain("certs/certchain.pem", "certs_kzi/leaf.key", &s) != 0) {



}

