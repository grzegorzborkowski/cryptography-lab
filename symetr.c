#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#define ERROR -1
#define SUCCESS 0

int encryption_algorithm; // Blowfish -> 0, DES -> 1
int is_encrypting_or_decrypting; // 1 for encryption, 0 for decryption
int encryption_mode; //  ECB -> 0, CBC -> 1

FILE *input_file;
FILE *output_file;

int parse_arguments(int argc, char *argv[]) {
    if (argc != 6) {
        printf("Usage: algorithm -encrypt|-decrypt -ecb|-cbc input_file output_file");
        return ERROR;
    }

    if (strcmp(argv[1], "BLOWFISH") == 0) {
        encryption_algorithm = 0;
    } else if (strcmp(argv[1], "DES") == 0) {
        encryption_algorithm = 1;
    } else {
        printf ("Unknown algortihm! \n");
        return ERROR;
    }

    if(strcmp(argv[2], "-encrypt") == 0) {
        is_encrypting_or_decrypting = 1;
    } else if(strcmp(argv[2], "-decrypt") == 0) {
        is_encrypting_or_decrypting = 0;
    } else {
        printf ("Unknown mode! \n");
        return ERROR;
    }

    if(strcmp(argv[3], "-ecb") == 0) {
        encryption_mode = 0;
    } else if(strcmp(argv[3], "-cbc") == 0) {
        encryption_mode = 1;
    } else {
        printf ("Unknown encryption mode \n");
        return ERROR;
    }

    return SUCCESS;
}

int open_files(char **argv) {
    if ((input_file = fopen(argv[4], "rb")) == NULL) {
        printf("%s: can not read input file %s\n", argv[0], argv[4]);
        return ERROR;
    }
    if ((output_file = fopen(argv[5], "wb")) == NULL) {
        printf("%s: can not read output file %s\n", argv[0], argv[5]);
        return ERROR;
    }
    return SUCCESS;
}

int close_files()
{
    fclose(input_file);
    fflush(output_file);
    fclose(output_file);
    return SUCCESS;
}

int do_crypt(FILE *input_file, FILE *output_file, int do_encrypt) {
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;

    unsigned char key[] = "0123456789abcdeF";
    // iv stands for initialization vector
    unsigned char iv[] = "1234567887654321";

    ctx = EVP_CIPHER_CTX_new();
    int initRes;
    if (encryption_algorithm == 0 && encryption_mode == 0) {
        // blowfish, ecb
        initRes = EVP_CipherInit_ex(ctx, EVP_bf_ecb(), NULL, NULL, NULL, is_encrypting_or_decrypting);
    }
    else if (encryption_algorithm == 0 && encryption_mode == 1) {
        // blowfish, cbc
        initRes = EVP_CipherInit_ex(ctx, EVP_bf_cbc(), NULL, NULL, NULL, is_encrypting_or_decrypting);
    } else if (encryption_algorithm == 1 && encryption_mode == 0) {
        // des, ecb
        initRes = EVP_CipherInit_ex(ctx, EVP_des_ecb(), NULL, NULL, NULL, is_encrypting_or_decrypting);
    } else if (encryption_algorithm == 1 && encryption_mode == 1) {
        // des, cbc
        initRes = EVP_CipherInit_ex(ctx, EVP_des_cbc(), NULL, NULL, NULL, is_encrypting_or_decrypting);
    }

    if (initRes == 0) {
        printf("Error when initalizing EVP_CipherInit");
        return ERROR;
    }

    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    for (;;) {
        inlen = fread(inbuf, 1, 1024, input_file);
        if (inlen <= 0) break;
        if(!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            EVP_CIPHER_CTX_free(ctx);
            return ERROR;
        }
       fwrite(outbuf, 1, outlen, output_file);
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
       EVP_CIPHER_CTX_free(ctx);
       return ERROR;
    }
    fwrite(outbuf, 1, outlen, output_file);
    EVP_CIPHER_CTX_free(ctx);
    return SUCCESS;
}


int main(int argc, char* argv[]) {
    int parse_arguments_result = parse_arguments(argc, argv);
    if (parse_arguments_result == ERROR) {
        printf("Error when parsing input arguments \n");
        return 0;
    }

    int open_files_result = open_files(argv);
    if (open_files_result == ERROR) {
        printf("Error while opening the files \n");
        close_files();
        return 0;
    }
    int cryption_result = do_crypt(input_file, output_file, is_encrypting_or_decrypting);
    if (cryption_result == ERROR) {
        printf("Error while doing encryption/decryption \n");
        close_files();
        return 0;
    }
    close_files();
    return 0;
}