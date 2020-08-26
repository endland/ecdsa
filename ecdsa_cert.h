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
#include <mbedtls/x509_crt.h>
#include <time.h>

#define Certificate_BYTES_SIZE 800
#define Certificate_ARRAY_SIZE 4

typedef struct session session_t;
struct session{
    uint64_t id;
  
    struct{
        uint8_t cert[Certificate_BYTES_SIZE]; 
        size_t cert_len;
        uint8_t sub_certs[Certificate_ARRAY_SIZE][Certificate_BYTES_SIZE]; 
        size_t subcert_len[Certificate_ARRAY_SIZE]; 
        mbedtls_ecdsa_context key;       // leaf private key
        mbedtls_ecdsa_context Sub2_key;  //public key
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
    } certificate;
};

int load_certificate_chain(const char *pemchain_path, const char *keyfile_path, session_t *s);