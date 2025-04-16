#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

#if __has_include("fileutil.h")
#include "fileutil.h"
#endif

#define PASS_LEN 50     // Maximum length any password will be.
#define HASH_LEN 33     // Length of hash plus one for null.

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s hash_file dictionary_file\n", argv[0]);
        exit(1);
    }

    // Loads hashes file into an array using loadFileAA
    int size;
    char **hashes = loadFileAA(argv[1], &size);

    // Opens file
    FILE *passFile = fopen(argv[2], "r");
    
    if (!passFile) {
        perror("Failed to open dictionary file");
        freeAA(hashes, size);
        exit(1);
    }

    char word[PASS_LEN];
    int crackedCount = 0;

    // Reads each password 
    while (fgets(word, PASS_LEN, passFile)) {
        word[strcspn(word, "\n")] = 0;

        // Hashes word
        unsigned char hashOutput[16];
        MD5((unsigned char*)word, strlen(word), hashOutput);

        char hashString[HASH_LEN];

        for (int i = 0; i < 16; i++) {
            sprintf(&hashString[i * 2], "%02x", (unsigned int)hashOutput[i]);
        }

        // Linear searches
        int foundIndex = linearSearch(hashes, size, hashString);

        if (foundIndex != -1) {
            printf("%s %s\n", hashString, word);
            crackedCount++;
        }
    }
    
    // Closes the file , frees memory, and displays number of hashes found
    fclose(passFile);
    freeAA(hashes, size);
    printf("%d hashes cracked!\n", crackedCount);
    return 0;
}

