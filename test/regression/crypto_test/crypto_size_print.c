/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  04/29/2020 04:45:06 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *        Company:  
 *
 * =====================================================================================
 */

#include <stdio.h>

#include "nx_crypto_phash.h"
#include "nx_crypto_tls_prf_1.h"
#include "nx_crypto_tls_prf_sha256.h"
#include "nx_crypto_tls_prf_sha384.h"
#include "nx_crypto_tls_prf_sha512.h"
#include "nx_crypto_hkdf.h"
#include "nx_crypto_3des.h"
#include "nx_crypto.h"
#include "nx_crypto_md5.h"
#include "nx_crypto_sha1.h"
#include "nx_crypto_sha2.h"
#include "nx_crypto_sha5.h"
#include "nx_crypto.h"
#include "nx_crypto_hmac_sha1.h"
#include "nx_crypto_hmac_sha2.h"
#include "nx_crypto_hmac_sha5.h"
#include "nx_crypto_hmac_md5.h"
#include "nx_crypto_aes.h"
#include "nx_crypto_rsa.h"
#include "nx_crypto_null.h"
#include "nx_crypto_ecjpake.h"
#include "nx_crypto_ecdsa.h"
#include "nx_crypto_ecdh.h"
#include "nx_crypto_drbg.h"
#include "nx_crypto_pkcs1_v1.5.h"
#include "nx_crypto_dh.h"
#include "nx_crypto_drbg.h"

int main()
{

   printf(" sizeof(NX_CRYPTO_AES),                             %d\n",      sizeof(NX_CRYPTO_AES));
   printf(" sizeof(NX_CRYPTO_DRBG),                            %d\n",      sizeof(NX_CRYPTO_DRBG));          
   printf(" sizeof(NX_CRYPTO_ECDSA),                           %d\n",      sizeof(NX_CRYPTO_ECDSA));         
   printf(" sizeof(NX_CRYPTO_ECDH),                            %d\n",      sizeof(NX_CRYPTO_ECDH));        
   printf(" sizeof(NX_CRYPTO_SHA1_HMAC),                       %d\n",      sizeof(NX_CRYPTO_SHA1_HMAC));
   printf(" sizeof(NX_CRYPTO_SHA256_HMAC),                     %d\n",      sizeof(NX_CRYPTO_SHA256_HMAC));
   printf(" sizeof(NX_CRYPTO_SHA512_HMAC),                     %d\n",      sizeof(NX_CRYPTO_SHA512_HMAC));  
   printf(" sizeof(NX_CRYPTO_MD5_HMAC),                        %d\n",      sizeof(NX_CRYPTO_MD5_HMAC));  
   printf(" sizeof(NX_CRYPTO_RSA),                             %d\n",      sizeof(NX_CRYPTO_RSA));     
   printf(" sizeof(NX_CRYPTO_ECJPAKE),                         %d\n",      sizeof(NX_CRYPTO_ECJPAKE));
   printf(" sizeof(NX_CRYPTO_MD5),                             %d\n",      sizeof(NX_CRYPTO_MD5));      
   printf(" sizeof(NX_CRYPTO_SHA1),                            %d\n",      sizeof(NX_CRYPTO_SHA1));          
   printf(" sizeof(NX_CRYPTO_SHA256),                          %d\n",      sizeof(NX_CRYPTO_SHA256));        
 //  printf(" sizeof(NX_CRYPTO_SHA384),                          %d\n",      sizeof(NX_CRYPTO_SHA384));       
   printf(" sizeof(NX_CRYPTO_SHA512),                          %d\n",      sizeof(NX_CRYPTO_SHA512));       
   printf(" sizeof(NX_CRYPTO_TLS_PRF_1),                       %d\n",      sizeof(NX_CRYPTO_TLS_PRF_1));
   printf(" sizeof(NX_CRYPTO_TLS_PRF_SHA256),                  %d\n",      sizeof(NX_CRYPTO_TLS_PRF_SHA256));
   printf(" sizeof(NX_CRYPTO_TLS_PRF_SHA384),                  %d\n",      sizeof(NX_CRYPTO_TLS_PRF_SHA384));
   printf(" sizeof(NX_CRYPTO_TLS_PRF_SHA512),                  %d\n",      sizeof(NX_CRYPTO_TLS_PRF_SHA512));
   printf(" sizeof(NX_CRYPTO_HMAC),                            %d\n",      sizeof(NX_CRYPTO_HMAC));          
   printf(" sizeof(NX_CRYPTO_HKDF) + sizeof(NX_CRYPTO_HMAC),   %d\n",      sizeof(NX_CRYPTO_HKDF) + sizeof(NX_CRYPTO_HMAC));
   printf(" sizeof(NX_CRYPTO_DES),                             %d\n",      sizeof(NX_CRYPTO_DES));
   printf(" sizeof(NX_CRYPTO_3DES),                            %d\n",      sizeof(NX_CRYPTO_3DES));                     
   printf(" sizeof(NX_CRYPTO_PKCS1),                           %d\n",      sizeof(NX_CRYPTO_PKCS1));
   printf(" sizeof(NX_CRYPTO_DH),                           %d\n",      sizeof(NX_CRYPTO_DH));
   printf(" sizeof(NX_CRYPTO_DRBG),                           %d\n",      sizeof(NX_CRYPTO_DRBG));

   return(0);

}
