SGX_SDK ?= /opt/intel/sgxsdk
SGX_INC ?= $(SGX_SDK)/include

CFLAGS += \
	-m64 \
	-Wall \
	-Wextra \
	-Werror \
	-D_GNU_SOURCE \
	-fPIC \
	-fstack-protector \
	-I$(SGX_INC) \
	-I../common \
	-std=c11

LDFLAGS += -Wl,-rpath=. -L../common -lsgx_util
APP_BIN ?= verify_ias_report
PREFIX ?= /usr/local

.PHONY: all
all: $(APP_BIN)

$(APP_BIN): $(APP_BIN).o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: install
install:
ifeq ($(PREFIX), $(DEFAULT_PREFIX))
	install -D $(APP_BIN) -t $(PREFIX)/bin
else
	install -D $(APP_BIN) -t $(PREFIX)
endif

.PHONY: clean
clean:
	$(RM) *.o $(APP_BIN)

.PHONY: distclean
distclean: clean
