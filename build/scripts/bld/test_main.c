#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Declare the fuzzer function
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <test_file>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("Cannot open file: %s\n", argv[1]);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size <= 0 || size > 1000000) {
        printf("Invalid file size: %ld\n", size);
        fclose(f);
        return 1;
    }
    
    uint8_t *data = malloc(size);
    if (!data) {
        printf("Memory allocation failed\n");
        fclose(f);
        return 1;
    }
    
    size_t read_size = fread(data, 1, size, f);
    fclose(f);
    
    if (read_size != size) {
        printf("Read error\n");
        free(data);
        return 1;
    }
    
    printf("Testing with %zu bytes...\n", size);
    int result = LLVMFuzzerTestOneInput(data, size);
    printf("Fuzzer returned: %d\n", result);
    
    free(data);
    return 0;
}
