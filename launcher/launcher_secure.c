#define _GNU_SOURCE
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

// Simple zeroizer
void zeroize(void *ptr, size_t len) {
    if (ptr) {
        volatile unsigned char *p = ptr;
        while (len--) *p++ = 0;
    }
}

// wrapper for memfd_create
static int memfd_create_wrap(const char *name, unsigned int flags) {
    return syscall(SYS_memfd_create, name, flags);
}

void die(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char **argv) {
    int debug = 0;
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <enc-file> <key-file> [--debug]\n", argv[0]);
        return 2;
    }
    if (argc == 4 && strcmp(argv[3], "--debug") == 0) {
        debug = 1;
    }

    const char *encf = argv[1], *keyf = argv[2];

    /* Read key */
    FILE *kf = fopen(keyf, "rb");
    if (!kf) die("open key");
    unsigned char key[32];
    if (fread(key, 1, 32, kf) != 32) die("read key");
    fclose(kf);

    /* Read encrypted file */
    struct stat st;
    if (stat(encf, &st) < 0) die("stat encfile");
    size_t fsize = st.st_size;
    FILE *ef = fopen(encf, "rb");
    if (!ef) die("open encfile");
    unsigned char *fbuf = malloc(fsize);
    if (!fbuf) die("alloc fbuf");
    if (fread(fbuf, 1, fsize, ef) != fsize) die("read encfile");
    fclose(ef);

    if (fsize < 12 + 16) {
        fprintf(stderr, "enc file too small\n");
        return 1;
    }

    unsigned char iv[12];
    memcpy(iv, fbuf, 12);
    size_t ctlen = fsize - 12 - 16;
    unsigned char *ct = fbuf + 12;
    unsigned char tag[16];
    memcpy(tag, fbuf + 12 + ctlen, 16);

    /* Decrypt using EVP AES-256-GCM */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) die("EVP_CIPHER_CTX_new");
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) die("EVP_DecryptInit_ex algo");
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL)) die("EVP_CIPHER_CTX_ctrl ivlen");
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) die("EVP_DecryptInit_ex key");

    unsigned char *pt = malloc(ctlen + 16);
    if (!pt) die("alloc pt");
    int outl = 0, tmplen = 0;
    if (1 != EVP_DecryptUpdate(ctx, pt, &outl, ct, (int)ctlen)) die("EVP_DecryptUpdate");
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) die("EVP_CIPHER_CTX_ctrl tag");
    if (1 != EVP_DecryptFinal_ex(ctx, pt + outl, &tmplen)) {
        fprintf(stderr, "DecryptFinal_ex failed: tag mismatch or corruption\n");
        exit(2);
    }
    outl += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    /* Create memfd and write plaintext into it */
    int mfd = memfd_create_wrap("ariadne_payload", MFD_CLOEXEC);
    if (mfd < 0) die("memfd_create");
    if (ftruncate(mfd, outl) < 0) die("ftruncate memfd");
    size_t off = 0;
    while (off < (size_t)outl) {
        ssize_t w = write(mfd, pt + off, outl - off);
        if (w <= 0) die("write memfd");
        off += w;
    }

    /* set exec permission */
    if (fchmod(mfd, 0700) < 0) die("fchmod");

    /* optional: mmap + mlock (best-effort) */
    void *map = mmap(NULL, outl, PROT_READ, MAP_SHARED, mfd, 0);
    if (map != MAP_FAILED) {
        mlock(map, outl); // nonfatal if fails
    }

    if (!debug) {
        clearenv();
        setenv("PATH", "/usr/bin:/bin", 1);
    }

    // Exec with argv0 = "my_app" for easier pgrep
    char *const argv_new[] = { "my_app", NULL };
    char *const env_new[]  = { NULL };

    if (debug) {
        fprintf(stderr, "[DEBUG] memfd fd=%d. Inspect via /proc/$(pgrep my_app)/fd\n", mfd);
        fprintf(stderr, "[DEBUG] launching via fexecve on fd=%d (PID=%d)\n", mfd, getpid());
        fflush(stderr);
    }

    if (fexecve(mfd, argv_new, env_new) < 0) {
        perror("fexecve");
        // fallback via /proc/self/fd/<mfd>
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", mfd);
        execl(path, "my_app", (char*)NULL);
        die("execl fallback");
    }

    // unreachable if exec succeeds
    zeroize(fbuf, fsize);
    zeroize(pt, outl);
    free(fbuf);
    free(pt);
    return 0;
}
