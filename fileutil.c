#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fileutil.h"

// Array of arrayss
char ** loadFileAA(char *filename, int *size) {
    FILE *in = fopen(filename, "r");
    if (!in) {
        perror("Can't open file");
        exit(1);
    }

    int capacity = 10; 
    *size = 0;         
    
    // Allocates memory for an array of strings (arr).
    char **arr = malloc(capacity * sizeof(char *));
    if (!arr) {
        perror("Failed to allocate memory for array");
        exit(1);
    }

    char temp[1000]; // temp to hold each line read from file
    
	// Reads file line by line
    while (fgets(temp, sizeof(temp), in)) {

        // Trims newline 
        char *newline = strchr(temp, '\n');
        if (newline) *newline = '\0';

        // Expands array if needed
        if (*size >= capacity){
            capacity *= 2;
            char **tempArr = realloc(arr, capacity * sizeof(char *));
            if (!tempArr) {
                perror("Failed to realloc array");

                // Cleans up allocated memory before exiting
                for (int i = 0; i < *size; i++) free(arr[i]);
                free(arr);
                exit(1);
            }
            arr = tempArr;
        }

        // Allocates memory for each string
        int len = strlen(temp);
        char *str = malloc(len + 1);
        if (!str) {
            perror("Failed to allocate memory for string");

            // Cleans up allocated memory before exiting
            for (int i = 0; i < *size; i++) free(arr[i]);
            free(arr);
            exit(1);
        }

        strcpy(str, temp); // Copies string into allocated memory
        arr[*size] = str;  // Adds string to the array
        (*size)++;         // Increments count
    }

    fclose(in); // Closes file
    return arr; // Returns array of strings
}

// Search the array for the target string.
// Return the found string or NULL if not found.
char * substringSearchAA(char *target, char **lines, int size) {
    for (int i = 0; i < size; i++) {

        // Uses strstr to check if target is found 
        if (strstr(lines[i], target)) {
            return lines[i]; // Returns first matching line
        }
    }
    return NULL; // No match found
}

// Frees memory used by array
void freeAA(char **arr, int size) {
    for (int i = 0; i < size; i++) {
        free(arr[i]); // Free each string
    }

    free(arr); // Free the array itself
}

// Linear searches
int linearSearch(char **array, int size, const char *target) {
    for (int i = 0; i < size; i++) {
        if (strcmp(array[i], target) == 0) {
            return i; // Return the index if match is found
        }
    }
    return -1; // Return -1 if no match is found
}

