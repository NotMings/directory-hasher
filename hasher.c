#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <math.h>
#include <unistd.h>

#define MAX_DIR_PATH_SIZE 4096
#define TEMP_FILE_PATH "/tmp/hasher.temp"

char *get_file_sha(char *file_path)
{
    if (file_path == NULL)
    {
        return "error";
    }

    char buffer[4096];
    size_t bytes;
    SHA256_CTX sha_ctx;
    unsigned char digest[SHA256_DIGEST_LENGTH];

    FILE *fp = fopen(file_path, "rb");
    if (!fp)
    {
        printf("open file %s error\n", file_path);
        return "error";
    }

    SHA256_Init(&sha_ctx);

    while ((bytes = fread(buffer, 1, sizeof(buffer), fp)))
    {
        SHA256_Update(&sha_ctx, buffer, 1024);
    }

    if (ferror(fp))
    {
        printf("read file %s error\n", file_path);
        return "error";
    }

    SHA256_Final(digest, &sha_ctx);

    fclose(fp);

    int i;
    char *result = (char *)malloc(sizeof(char) * 255);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(result + 2 * i, "%02x", digest[i]);
    }
    result[2 * i] = '\0';
    return result;
}

long int file_numbers = 0;
void get_dir_sha(const char *base_dir_path)
{
    char *dirent_path = (char *)malloc(MAX_DIR_PATH_SIZE);
    char *sha_value;

    DIR *dir = NULL;
    struct dirent *entry;
    struct stat fileinfo;
    FILE *fp = NULL;

    if (!(dir = opendir(base_dir_path)))
    {
        return;
    }

    while ((entry = readdir(dir)) != NULL)
    {
        if ((!strcmp(entry->d_name, ".")) || (!strcmp(entry->d_name, "..")))
        {
            continue;
        }

        strcpy(dirent_path, base_dir_path);
        strcat(dirent_path, "/");
        strcat(dirent_path, entry->d_name);

        stat(dirent_path, &fileinfo);
        if (S_ISDIR(fileinfo.st_mode))
        {
            get_dir_sha(dirent_path);
        }
        else
        {
            file_numbers++;
            sha_value = get_file_sha(dirent_path);
            if (fp == NULL)
            {
                fp = fopen(TEMP_FILE_PATH, "a+");
            }

            if ((sha_value != NULL) && (fp != NULL))
            {
                fprintf(fp, "%s", sha_value);
            }

            if (fp != NULL)
            {
                fclose(fp);
            }
            fp = NULL;
        }
    }
    closedir(dir);

    return;
}

int main(int argc, char const *argv[])
{
    if (argv[1] == NULL)
    {
        char dir_path[MAX_DIR_PATH_SIZE];
        getcwd(dir_path, MAX_DIR_PATH_SIZE);
        argv[1] = dir_path;
    }

    printf("the selected dir path is: %s\n", argv[1]);

    get_dir_sha(argv[1]);

    printf("file numbers: %d\n", file_numbers);

    char *sha_value;
    sha_value = get_file_sha(TEMP_FILE_PATH);

    remove(TEMP_FILE_PATH);

    printf("dir hash is: %s\n", sha_value);

    return 0;
}