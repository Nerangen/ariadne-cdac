// scripts/encrypt_payload.c
#define _GNU_SOURCE
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void die(const char *m){ perror(m); exit(1); }

int main(int argc, char **argv){
    if(argc!=4){
        fprintf(stderr, "Usage: %s <input-bin> <key-file-32b> <output-enc>\n", argv[0]);
        return 2;
    }
    const char *in = argv[1], *keyf = argv[2], *out = argv[3];

    // read key
    FILE *kf = fopen(keyf,"rb"); if(!kf) die("open key");
    unsigned char key[32];
    if(fread(key,1,32,kf)!=32) die("read key");
    fclose(kf);

    // read input
    struct stat st; if(stat(in,&st)<0) die("stat input");
    size_t inlen = st.st_size;
    unsigned char *inbuf = malloc(inlen);
    if(!inbuf) die("malloc inbuf");
    FILE *inf = fopen(in,"rb"); if(!inf) die("open input");
    if(fread(inbuf,1,inlen,inf)!=inlen) die("read input");
    fclose(inf);

    // make IV
    unsigned char iv[12];
    if(RAND_bytes(iv,sizeof(iv))!=1){ fprintf(stderr,"RAND_bytes failed\n"); exit(1); }

    // encrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx){ fprintf(stderr,"EVP new failed\n"); exit(1); }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)!=1) die("enc init");
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL)!=1) die("ivlen");
    if(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)!=1) die("key+iv");

    unsigned char *ct = malloc(inlen + 32);
    if(!ct) die("malloc ct");
    int outl=0, tm=0;

    if(EVP_EncryptUpdate(ctx, ct, &outl, inbuf, (int)inlen)!=1) die("enc update");
    if(EVP_EncryptFinal_ex(ctx, ct+outl, &tm)!=1) die("enc final");
    outl += tm;

    unsigned char tag[16];
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag)!=1) die("get tag");

    EVP_CIPHER_CTX_free(ctx);

    // write [IV || CT || TAG]
    FILE *of = fopen(out,"wb"); if(!of) die("open out");
    if(fwrite(iv,1,sizeof(iv),of)!=sizeof(iv)) die("write iv");
    if(fwrite(ct,1,outl,of)!=(size_t)outl) die("write ct");
    if(fwrite(tag,1,sizeof(tag),of)!=sizeof(tag)) die("write tag");
    fclose(of);

    // scrub key memory best-effort
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(inbuf, inlen);
    OPENSSL_cleanse(ct, outl);
    free(inbuf); free(ct);

    fprintf(stdout, "encryption done: %s -> %s\n", in, out);
    return 0;
}
