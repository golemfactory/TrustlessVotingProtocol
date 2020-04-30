/* Copyright (C) 2018-2020 Invisible Things Lab
                           Rafal Wojdyla <omeg@invisiblethingslab.com>
   This file is part of Graphene Library OS.
   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.
   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <mbedtls/entropy.h>

#include "util.h"

/*! Console stdout fd */
int g_stdout_fd = 1;

/*! Console stderr fd */
int g_stderr_fd = 2;

/*! Verbosity level */
bool g_verbose = false;

/*! Endianness for hex strings */
endianness_t g_endianness = ENDIAN_LSB;

void set_verbose(bool verbose) {
    g_verbose = verbose;
    if (verbose)
        DBG("Verbose output enabled\n");
    else
        DBG("Verbose output disabled\n");
}

bool get_verbose(void) {
    return g_verbose;
}

void set_endianness(endianness_t endianness) {
    g_endianness = endianness;
    if (g_verbose) {
        if (endianness == ENDIAN_LSB)
            DBG("Endianness set to LSB\n");
        else
            DBG("Endianness set to MSB\n");
    }
}

endianness_t get_endianness(void) {
    return g_endianness;
}

/* return -1 on error */
ssize_t get_file_size(int fd) {
    struct stat st;

    if (fstat(fd, &st) != 0)
        return -1;

    return st.st_size;
}

void* read_file(const char* path, void* buffer, size_t* size) {
    FILE* f = NULL;
    ssize_t fs = 0;
    void* buf = buffer;

    if (!size || !path)
        return NULL;

    f = fopen(path, "rb");
    if (!f) {
        ERROR("Failed to open file '%s' for reading: %s\n", path, strerror(errno));
        goto out;
    }

    if (*size == 0) { // read whole file
        fs = get_file_size(fileno(f));
        if (fs < 0) {
            ERROR("Failed to get size of file '%s': %s\n", path, strerror(errno));
            goto out;
        }
    } else {
        fs = *size;
    }

    if (!buffer) {
        buffer = malloc(fs);
        if (!buffer) {
            ERROR("No memory\n");
            goto out;
        }
    }

    if (fread(buffer, fs, 1, f) != 1) {
        ERROR("Failed to read file '%s'\n", path);
        if (!buf) {
            free(buffer);
            buffer = NULL;
        }
    }

out:
    if (f)
        fclose(f);

    if (*size == 0)
        *size = fs;

    return buffer;
}

static int write_file_internal(const char* path, const void* buffer, size_t size, bool append) {
    FILE* f = NULL;
    int status;

    if (append)
        f = fopen(path, "ab");
    else
        f = fopen(path, "wb");

    if (!f) {
        ERROR("Failed to open file '%s' for writing: %s\n", path, strerror(errno));
        goto out;
    }

    if (size > 0 && buffer) {
        if (fwrite(buffer, size, 1, f) != 1) {
            ERROR("Failed to write file '%s': %s\n", path, strerror(errno));
            goto out;
        }
    }

    errno = 0;

out:
    status = errno;
    if (f)
        fclose(f);
    return status;
}

/* Write buffer to file */
int write_file(const char* path, const void* buffer, size_t size) {
    return write_file_internal(path, buffer, size, false);
}

/* Append buffer to file */
int append_file(const char* path, const void* buffer, size_t size) {
    return write_file_internal(path, buffer, size, true);
}

/* Set stdout/stderr descriptors */
void util_set_fd(int stdout_fd, int stderr_fd) {
    g_stdout_fd = stdout_fd;
    g_stderr_fd = stderr_fd;
}

/* Print memory as hex in buffer */
int hexdump_mem_to_buffer(const void* data, size_t size, char* buffer, size_t buffer_size) {
    uint8_t* ptr = (uint8_t*)data;

    if (buffer_size < size * 2 + 1) {
        ERROR("Insufficiently large buffer to dump data as hex string\n");
        return -1;
    }

    for (size_t i = 0; i < size; i++) {
        if (g_endianness == ENDIAN_LSB) {
            sprintf(buffer + i * 2, "%02x", ptr[i]);
        } else {
            sprintf(buffer + i * 2, "%02x", ptr[size - i - 1]);
        }
    }

    buffer[size * 2] = 0; /* end of string */
    return 0;
}

/* Print memory as hex */
void hexdump_mem(const void* data, size_t size) {
    uint8_t* ptr = (uint8_t*)data;

    for (size_t i = 0; i < size; i++) {
        if (g_endianness == ENDIAN_LSB) {
            INFO("%02x", ptr[i]);
        } else {
            INFO("%02x", ptr[size - i - 1]);
        }
    }

    INFO("\n");
}

/* Parse hex string to buffer */
int parse_hex(const char* hex, void* buffer, size_t buffer_size) {
    if (!hex || !buffer || buffer_size == 0)
        return -1;

    if (strlen(hex) != buffer_size * 2) {
        ERROR("Invalid hex string (%s) length\n", hex);
        return -1;
    }

    for (size_t i = 0; i < buffer_size; i++) {
        if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1])) {
            ERROR("Invalid hex string '%s'\n", hex);
            return -1;
        }

        if (g_endianness == ENDIAN_LSB)
            sscanf(hex + i * 2, "%02hhx", &((uint8_t*)buffer)[i]);
        else
            sscanf(hex + i * 2, "%02hhx", &((uint8_t*)buffer)[buffer_size - i - 1]);
    }
    return 0;
}

char* read_line(void) {
    size_t buf_size = 256;
    char* str = malloc(buf_size);
    if (!str)
        return NULL;
    int c;
    size_t len = 0;

    while ((c = getchar()) != EOF && c != '\n') {
        str[len++] = c;
        if (len == buf_size) {
            buf_size *= 2;
            char* old = str;
            str = realloc(str, buf_size);
            if (!str) {
                free(old);
                return NULL;
            }
        }
    }

    str[len] = '\0';
    return str;
}

/* Returns 0 on failure */
sgx_enclave_id_t enclave_load(const char* enclave_path, bool debug_enabled) {
    int is_token_updated = 0;
    sgx_launch_token_t launch_token = {0}; // TODO: cache the token
    sgx_misc_attribute_t misc_attribs = {0};
    sgx_enclave_id_t enclave_id = 0;

    INFO("Loading enclave from file '%s'\n", enclave_path);

    sgx_status_t sgx_ret = sgx_create_enclave(enclave_path, debug_enabled, &launch_token,
                                              &is_token_updated, &enclave_id, &misc_attribs);
    if (sgx_ret != SGX_SUCCESS) {
        ERROR("Failed to load enclave: %d\n", sgx_ret);
    } else {
        INFO("Enclave loaded successfully, id = 0x%lx\n", enclave_id);
    }

    return enclave_id;
}

sgx_status_t enclave_unload(sgx_enclave_id_t enclave_id) {
    sgx_status_t sgx_ret = sgx_destroy_enclave(enclave_id);
    if (sgx_ret != SGX_SUCCESS)
        ERROR("Failed to unload enclave\n");
    else
        INFO("Enclave unloaded\n");

    return sgx_ret;
}

// mbedtls callbacks
// TODO: this would not be needed if we rebuilt mbedtls a second time just for non-enclave binaries

void mbedtls_platform_zeroize(void* buf, size_t size) {
    // TODO: use proper function like memset_s (Ubuntu 16.04 has too old glibc)
    memset(buf, 0, size);
}

int mbedtls_hardware_poll(void* data, unsigned char* output, size_t len, size_t* olen) {
    (void)data; // not used
    assert(output && olen);
    *olen = 0;

    if (!read_file("/dev/urandom", output, &len)) {
        ERROR("Failed to read random data\n");
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    *olen = len;
    return 0;
}
