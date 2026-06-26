.PHONY: all clean
.DEFAULT_GOAL := all

CC := clang
MLDSA_NATIVE_DIR ?= /root/ACVP204/mldsa-native
MLDSA_DIR := $(MLDSA_NATIVE_DIR)/mldsa

BASE_CPPFLAGS := \
	-I$(MLDSA_DIR) \
	-I$(MLDSA_DIR)/src \
	-DMLD_CONFIG_NAMESPACE_PREFIX=mldsa

KEYGEN_CPPFLAGS := \
	$(BASE_CPPFLAGS) \
	-DMLD_CONFIG_NO_RANDOMIZED_API \
	-DMLD_CONFIG_NO_SIGN_API \
	-DMLD_CONFIG_NO_VERIFY_API

SIGGEN_CPPFLAGS := \
	$(BASE_CPPFLAGS) \
	-DMLD_CONFIG_NO_RANDOMIZED_API \
	-DMLD_CONFIG_NO_VERIFY_API

CFLAGS := \
	-std=c99 \
	-O3 \
	-Wall \
	-Wextra \
	-Wpedantic \
	-Werror=unused-result \
	-Wno-unknown-pragmas

MLDSA_SOURCES := \
	$(MLDSA_DIR)/src/ct.c \
	$(MLDSA_DIR)/src/debug.c \
	$(MLDSA_DIR)/src/packing.c \
	$(MLDSA_DIR)/src/poly.c \
	$(MLDSA_DIR)/src/poly_kl.c \
	$(MLDSA_DIR)/src/polyvec.c \
	$(MLDSA_DIR)/src/polyvec_lazy.c \
	$(MLDSA_DIR)/src/sign.c \
	$(MLDSA_DIR)/src/fips202/fips202.c \
	$(MLDSA_DIR)/src/fips202/fips202x4.c \
	$(MLDSA_DIR)/src/fips202/keccakf1600.c

KEYGEN_SOURCE := keygen_oracle.c
SIGGEN_SOURCE := siggen_oracle.c

KEYGEN_BIN44 := bin/mldsa44_keygen_oracle
KEYGEN_BIN65 := bin/mldsa65_keygen_oracle
KEYGEN_BIN87 := bin/mldsa87_keygen_oracle

SIGGEN_BIN44 := bin/mldsa44_siggen_oracle
SIGGEN_BIN65 := bin/mldsa65_siggen_oracle
SIGGEN_BIN87 := bin/mldsa87_siggen_oracle

all: $(KEYGEN_BIN44) $(KEYGEN_BIN65) $(KEYGEN_BIN87) $(SIGGEN_BIN44) $(SIGGEN_BIN65) $(SIGGEN_BIN87)

$(KEYGEN_BIN44): PARAMETER_SET := 44
$(KEYGEN_BIN65): PARAMETER_SET := 65
$(KEYGEN_BIN87): PARAMETER_SET := 87

$(SIGGEN_BIN44): PARAMETER_SET := 44
$(SIGGEN_BIN65): PARAMETER_SET := 65
$(SIGGEN_BIN87): PARAMETER_SET := 87

$(KEYGEN_BIN44) $(KEYGEN_BIN65) $(KEYGEN_BIN87): $(KEYGEN_SOURCE) $(MLDSA_SOURCES)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(KEYGEN_CPPFLAGS) -DMLD_CONFIG_PARAMETER_SET=$(PARAMETER_SET) $^ -o $@

$(SIGGEN_BIN44) $(SIGGEN_BIN65) $(SIGGEN_BIN87): $(SIGGEN_SOURCE) $(MLDSA_SOURCES)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(SIGGEN_CPPFLAGS) -DMLD_CONFIG_PARAMETER_SET=$(PARAMETER_SET) $^ -o $@

clean:
	rm -rf bin
