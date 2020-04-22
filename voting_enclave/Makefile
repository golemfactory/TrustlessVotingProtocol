SGX_SDK ?= /opt/intel/sgxsdk
MBEDTLS ?= mbedtls
MBEDTLS_INC ?= $(MBEDTLS)/include
MBEDTLS_LIB ?= $(MBEDTLS)/library
SGX_INC ?= $(SGX_SDK)/include
SGX_LIB ?= $(SGX_SDK)/lib64

ENCLAVE_NAME ?= voting_enclave
ENCLAVE_CONFIG ?= $(ENCLAVE_NAME).config.xml
ENCLAVE_SIGNING_PUBLIC_KEY ?= $(ENCLAVE_NAME)_signing_pubkey.pem
ENCLAVE_BINARY ?= $(ENCLAVE_NAME).so
ENCLAVE_BINARY_SIGNED ?= $(ENCLAVE_NAME).signed.so

LIBRARY_NAME ?= ve_user
LIBRARY_BIN ?= lib$(LIBRARY_NAME).so
APP_NAME ?= ve_app
APP_BIN ?= $(APP_NAME)

DEFAULT_PREFIX := /usr/local
PREFIX ?= $(DEFAULT_PREFIX)

MBEDTLS_VERSION ?= 2.22.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= https://github.com/ARMmbed/mbedtls/archive/
MBEDTLS_CHECKSUM ?= 94ac6bdd209248028bd94b20bfac769e7922dda15c40c67a6170b0a58e7982f4

##############################################################################

ifeq ($(DEBUG), 1)
    CFLAGS += -O0 -g
    MBED_BUILD_TYPE = Debug
else
    CFLAGS += -O2
    MBED_BUILD_TYPE = Release
endif

CFLAGS += \
    -m64 \
    -Wall \
    -Wextra \
    -Werror \
    -D_GNU_SOURCE \
    -fPIC \
    -fstack-protector \
    -I$(SGX_INC) \
    -std=c11

.PHONY: all
all: check_key $(ENCLAVE_BINARY_SIGNED) $(LIBRARY_BIN) $(APP_BIN)

$(MBEDTLS_SRC):
	./download.sh --output $@ --url $(MBEDTLS_URI)/$(MBEDTLS_SRC) --sha256 $(MBEDTLS_CHECKSUM)
	tar -mxzf $(MBEDTLS_SRC)
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) $(MBEDTLS)
	patch -p1 --forward < mbedtls.patch

.PHONY:
mbedtls: $(MBEDTLS_SRC) mbedtls_config.h
	cp mbedtls_config.h $(MBEDTLS)/include/mbedtls/config.h
	cd mbedtls && make CFLAGS="-fPIC" lib && cd ..

##############################################################################
# enclave

CFLAGS_ENCLAVE := $(CFLAGS) \
    -nostdinc \
    -I$(SGX_INC)/tlibc \
    -I$(MBEDTLS_INC)

LDFLAGS_ENCLAVE := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
    -L$(SGX_LIB) \
    -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
    -Wl,--defsym,__ImageBase=0

SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
EDGER8R_FLAGS := --search-path $(SGX_INC)
MRSIGNER := $(ENCLAVE_NAME).mrsigner
MRSIGNER_H := $(ENCLAVE_NAME)_mrsigner.h

MBEDTLS_OBJS_ENCLAVE := \
    $(MBEDTLS_LIB)/aes.o \
    $(MBEDTLS_LIB)/aesni.o \
	$(MBEDTLS_LIB)/asn1parse.o \
	$(MBEDTLS_LIB)/asn1write.o \
	$(MBEDTLS_LIB)/bignum.o \
    $(MBEDTLS_LIB)/ctr_drbg.o \
	$(MBEDTLS_LIB)/ecdsa.o \
	$(MBEDTLS_LIB)/ecp.o \
	$(MBEDTLS_LIB)/ecp_curves.o \
    $(MBEDTLS_LIB)/entropy.o \
	$(MBEDTLS_LIB)/sha256.o

.PHONY: check_key
check_key:
ifndef ENCLAVE_SIGNING_KEY
	$(error ENCLAVE_SIGNING_KEY not set)
endif

$(ENCLAVE_SIGNING_PUBLIC_KEY): $(ENCLAVE_SIGNING_KEY)
	openssl rsa -in $(ENCLAVE_SIGNING_KEY) -pubout -out $(ENCLAVE_SIGNING_PUBLIC_KEY)

$(ENCLAVE_BINARY_SIGNED): $(ENCLAVE_BINARY) $(ENCLAVE_SIGNING_KEY) $(ENCLAVE_SIGNING_PUBLIC_KEY)
	$(SGX_SIGNER) gendata -enclave $< -out $<.sigdata -config $(ENCLAVE_CONFIG) -ignore-init-sec-error
	# replace the command below to use HSM for signing operation
	openssl dgst -sha256 -out $<.sig -sign $(ENCLAVE_SIGNING_KEY) $<.sigdata
	$(SGX_SIGNER) catsig -enclave $< -sig $<.sig \
		-unsigned $<.sigdata -key $(ENCLAVE_SIGNING_PUBLIC_KEY) -out $@ \
		-config $(ENCLAVE_CONFIG) -ignore-init-sec-error
	$(SGX_SIGNER) dump -enclave $@ -dumpfile enclave.meta -ignore-init-sec-error

$(MRSIGNER): $(ENCLAVE_SIGNING_PUBLIC_KEY) openssl_parse.awk
	openssl rsa -in $(ENCLAVE_SIGNING_PUBLIC_KEY) -pubin -text -noout \
		| awk -f openssl_parse.awk | xxd -p -r | sha256sum -b \
		| xxd -r -ps -l 32 > $@

# header with mrsigner value
$(MRSIGNER_H): $(MRSIGNER)
	xxd -i -c 8 $(MRSIGNER) > $@

$(ENCLAVE_BINARY): $(ENCLAVE_NAME)_t.o $(ENCLAVE_NAME).o mbedtls
	$(CC) $(ENCLAVE_NAME)_t.o $(ENCLAVE_NAME).o $(MBEDTLS_OBJS_ENCLAVE) $(LDFLAGS_ENCLAVE) -o $@

$(ENCLAVE_NAME).o: $(ENCLAVE_NAME).c $(MRSIGNER_H) $(ENCLAVE_NAME)_u.c mbedtls
	$(CC) $(CFLAGS_ENCLAVE) -c $< -o $@

$(ENCLAVE_NAME)_t.o: $(ENCLAVE_NAME)_t.c
	$(CC) $(CFLAGS_ENCLAVE) -c $< -o $@

# ECALL/OCALL interface (generated files)
$(ENCLAVE_NAME)_t.c: $(ENCLAVE_NAME).edl
	$(SGX_EDGER8R) $(EDGER8R_FLAGS) --trusted $<

$(ENCLAVE_NAME)_u.c: $(ENCLAVE_NAME).edl
	$(SGX_EDGER8R) $(EDGER8R_FLAGS) --untrusted $<

##############################################################################
# untrusted library

CFLAGS_LIB := $(CFLAGS) \
    -I$(MBEDTLS_INC)

MBEDTLS_OBJS_LIB := \
	$(MBEDTLS_LIB)/sha256.o

LDFLAGS_LIB := -lcrypto \
    -L$(SGX_LIB) -lsgx_urts -lsgx_uae_service \
    -shared

$(LIBRARY_BIN): $(LIBRARY_NAME).o $(ENCLAVE_NAME)_u.o
	$(CC) $^ $(MBEDTLS_OBJS_LIB) $(LDFLAGS_LIB) -o $@

$(LIBRARY_NAME).o: $(LIBRARY_NAME).c
	$(CC) $(CFLAGS_LIB) -c $< -o $@

$(ENCLAVE_NAME)_u.o: $(ENCLAVE_NAME)_u.c
	$(CC) $(CFLAGS_LIB) -c $< -o $@

##############################################################################
# application

$(APP_BIN): $(APP_NAME).o $(LIBRARY_BIN)
	$(CC) $(LDFLAGS) -Wl,-rpath=. $< -o $@ -L. -l$(LIBRARY_NAME)

$(APP_NAME).o: $(APP_NAME).c
	$(CC) $(CFLAGS) -c $< -o $@

##############################################################################

.PHONY: install
install:
	install -D $(LIBRARY_BIN) ${PREFIX}/lib
	install -D $(APP_BIN) ${PREFIX}/bin

ifeq ($(PREFIX), $(DEFAULT_PREFIX))
	ldconfig
else
	ldconfig -n ${PREFIX}/lib
endif

##############################################################################

.PHONY: clean
clean:
	$(RM) *.gz *.o *.so $(APP_BIN)
	$(RM) $(ENCLAVE_NAME)_t.c $(ENCLAVE_NAME)_t.h $(ENCLAVE_NAME)_u.c $(ENCLAVE_NAME)_u.h
	$(RM) *.meta *.mrsigner *_mrsigner.h *.sig *.sigdata $(ENCLAVE_SIGNING_PUBLIC_KEY)
	$(RM) -r mbedtls
