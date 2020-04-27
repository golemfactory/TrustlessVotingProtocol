SGX_SDK ?= /opt/intel/sgxsdk
SGX_INC ?= $(SGX_SDK)/include
SGX_LIB ?= $(SGX_SDK)/lib64
MBEDTLS ?= ../common/mbedtls
MBEDTLS_INC ?= $(MBEDTLS)/include
MBEDTLS_LIB ?= $(MBEDTLS)/library

LIBRARY_NAME ?= tvp_voter
LIBRARY_BIN ?= lib$(LIBRARY_NAME).so
APP_NAME ?= voter_app
APP_BIN ?= $(APP_NAME)

DEFAULT_PREFIX := /usr/local
PREFIX ?= $(DEFAULT_PREFIX)

##############################################################################

ifeq ($(DEBUG), 1)
	CFLAGS += -O0 -g -DDEBUG
else
	CFLAGS += -O2
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
	-I$(MBEDTLS_INC) \
	-I../common \
	-I../include \
	-std=c11

.PHONY: all
all: $(LIBRARY_BIN) $(APP_BIN)

##############################################################################
# voter library

CFLAGS_LIB := $(CFLAGS)

MBEDTLS_OBJS_LIB := \
	$(MBEDTLS_LIB)/sha256.o

LDFLAGS_LIB := \
	-L../common -lsgx_util \
	-shared

$(LIBRARY_BIN): $(LIBRARY_NAME).o
	$(CC) $^ $(MBEDTLS_OBJS_LIB) $(LDFLAGS_LIB) -o $@

$(LIBRARY_NAME).o: $(LIBRARY_NAME).c
	$(CC) $(CFLAGS_LIB) -c $< -o $@

##############################################################################
# application

MBEDTLS_OBJS_APP := \
	$(MBEDTLS_LIB)/sha256.o

$(APP_BIN): $(APP_NAME).o $(LIBRARY_BIN)
	$(CC) $(LDFLAGS) -Wl,-rpath=. $< $(MBEDTLS_OBJS_APP) \
	-o $@ -L. -l$(LIBRARY_NAME) -L../common -lsgx_util

$(APP_NAME).o: $(APP_NAME).c
	$(CC) $(CFLAGS) -c $< -o $@

##############################################################################

.PHONY: install
install:

ifeq ($(PREFIX), $(DEFAULT_PREFIX))
	install -D $(LIBRARY_BIN) -t $(PREFIX)/lib
	install -D $(APP_BIN) -t $(PREFIX)/bin
	ldconfig
else
	install -D $(LIBRARY_BIN) -t $(PREFIX)
	install -D $(APP_BIN) -t $(PREFIX)
	ldconfig -n $(PREFIX)
endif

##############################################################################
.PHONY: distclean
distclean: clean

.PHONY: clean
clean:
	$(RM) *.o *.so $(APP_BIN)
