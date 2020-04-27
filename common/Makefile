SGX_SDK ?= /opt/intel/sgxsdk
SGX_INC ?= $(SGX_SDK)/include
SGX_LIB ?= $(SGX_SDK)/lib64
MBEDTLS ?= mbedtls
MBEDTLS_INC ?= $(MBEDTLS)/include
MBEDTLS_LIB ?= $(MBEDTLS)/library

LIBRARY_NAME ?= sgx_util
LIBRARY_BIN ?= lib$(LIBRARY_NAME).so

CFLAGS += \
	-m64 \
	-Wall \
	-Wextra \
	-Werror \
	-D_GNU_SOURCE \
	-D_POSIX_C_SOURCE=200809L \
	-fPIC \
	-fstack-protector \
	-I$(SGX_INC) \
	-I$(MBEDTLS_INC) \
	-I../include \
	-std=c11

ifeq ($(DEBUG), 1)
	CFLAGS += -O0 -g -DDEBUG
	MBED_BUILD_TYPE = Debug
else
	CFLAGS += -O2
	MBED_BUILD_TYPE = Release
endif

LDFLAGS += -L$(MBEDTLS_LIB) -L$(SGX_LIB)

DEFAULT_PREFIX := /usr/local
PREFIX ?= $(DEFAULT_PREFIX)

COMMON_OBJS := crypto_utils.o

.PHONY: all
all: $(LIBRARY_BIN) $(COMMON_OBJS)

##############################################################################

MBEDTLS_VERSION ?= 2.22.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= https://github.com/ARMmbed/mbedtls/archive/
MBEDTLS_CHECKSUM ?= 94ac6bdd209248028bd94b20bfac769e7922dda15c40c67a6170b0a58e7982f4

$(MBEDTLS_SRC):
	./download.sh --output $@ --url $(MBEDTLS_URI)/$(MBEDTLS_SRC) --sha256 $(MBEDTLS_CHECKSUM)

$(MBEDTLS): $(MBEDTLS_SRC)
	tar -mxzf $<
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) $@
	patch -p1 --forward < mbedtls.patch

$(MBEDTLS)/.build_succeeded: mbedtls_config.h $(MBEDTLS)
	cp $< $(MBEDTLS)/include/mbedtls/config.h
	cd $(MBEDTLS) && make CFLAGS="-fPIC" lib
	touch $@

CJSON_VERSION ?= 1.7.12
CJSON_SRC ?= v$(CJSON_VERSION).tar.gz
CJSON_URI ?= https://github.com/DaveGamble/cJSON/archive/
CJSON_CHECKSUM ?= 760687665ab41a5cff9c40b1053c19572bcdaadef1194e5cba1b5e6f824686e7

cJSON.c cJSON.h:
	./download.sh --output $(CJSON_SRC) --url $(CJSON_URI)/$(CJSON_SRC) --sha256 $(CJSON_CHECKSUM)
	tar -mxzf $(CJSON_SRC)
	cp cJSON-$(CJSON_VERSION)/cJSON.c .
	cp cJSON-$(CJSON_VERSION)/cJSON.h .

##############################################################################

attestation.o: cJSON.h $(MBEDTLS)/.build_succeeded

util.o ias.o: $(MBEDTLS)/.build_succeeded

MBEDTLS_OBJS := \
	$(MBEDTLS_LIB)/aes.o \
	$(MBEDTLS_LIB)/aesni.o \
	$(MBEDTLS_LIB)/asn1parse.o \
	$(MBEDTLS_LIB)/asn1write.o \
	$(MBEDTLS_LIB)/base64.o \
	$(MBEDTLS_LIB)/bignum.o \
	$(MBEDTLS_LIB)/cipher.o \
	$(MBEDTLS_LIB)/cipher_wrap.o \
	$(MBEDTLS_LIB)/ctr_drbg.o \
	$(MBEDTLS_LIB)/ecdsa.o \
	$(MBEDTLS_LIB)/ecp.o \
	$(MBEDTLS_LIB)/ecp_curves.o \
	$(MBEDTLS_LIB)/entropy.o \
	$(MBEDTLS_LIB)/md.o \
	$(MBEDTLS_LIB)/oid.o \
	$(MBEDTLS_LIB)/pk.o \
	$(MBEDTLS_LIB)/pkcs5.o \
	$(MBEDTLS_LIB)/pkparse.o \
	$(MBEDTLS_LIB)/pk_wrap.o \
	$(MBEDTLS_LIB)/sha256.o

$(LIBRARY_BIN): attestation.o cJSON.o ias.o util.o $(MBEDTLS)/.build_succeeded
	$(CC) attestation.o cJSON.o ias.o util.o $(MBEDTLS_OBJS) \
		-lcurl -lsgx_urts -lsgx_uae_service -shared -o $@

##############################################################################

crypto_utils.o: %.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

##############################################################################

.PHONY: install
install:

ifeq ($(PREFIX), $(DEFAULT_PREFIX))
	install -D $(LIBRARY_BIN) -t $(PREFIX)/lib
	ldconfig
else
	install -D $(LIBRARY_BIN) -t $(PREFIX)
	ldconfig -n $(PREFIX)
endif

.PHONY: clean
clean:
	$(RM) *.o *.so

.PHONY: distclean
distclean: clean
	$(RM) *.gz
	$(RM) -r cJSON-$(CJSON_VERSION) cJSON.c cJSON.h
	$(RM) -r $(MBEDTLS)
