# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SW
SGX_ARCH ?= x64

TOP_DIR := ../sgx
include $(TOP_DIR)/buildenv.mk

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

SGX_COMMON_CFLAGS += -fstack-protector

######## CUSTOM Settings ########

CUSTOM_LIBRARY_PATH := ./lib
CUSTOM_BIN_PATH := ./bin
CUSTOM_EDL_PATH := ../sgx/edl
CUSTOM_COMMON_PATH := ../sgx/common

APP=safety-rules
LIBRA_PATH=~/libra

######## EDL Settings ########

ENCLAVE=enclave
Enclave_EDL_Files := $(ENCLVAE)/Enclave_t.c $(ENCLAVE)/Enclave_t.h $(APP)/Enclave_u.c $(APP)/Enclave_u.h

######## APP Settings ########

##App_Rust_Flags := --release
App_Rust_Flags := --verbose
App_SRC_Files := $(shell find $(APP)/ -type f -name '*.rs') $(shell find $(APP)/ -type f -name 'Cargo.toml')
App_Include_Paths := -I ./$(APP) -I./include -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

#App_Rust_Path := ./$(APP)/target/debug
# lwg: due to libra workplace hack, build targets are in here
App_Rust_Path := $(LIBRA_PATH)/target/debug
App_Enclave_u_Object :=$(APP)/libEnclave_u.a
App_Name := bin/app

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto
KeyExchange_Library_Name := sgx_tkey_exchange
ProtectedFs_Library_Name := sgx_tprotected_fs

RustEnclave_C_Files := $(wildcard ./enclave/*.c)
RustEnclave_C_Objects := $(RustEnclave_C_Files:.c=.o)
RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I ./enclave -I./include

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lenclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) $(ENCLAVE_CFLAGS) $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Service_Library_Name) -l$(Crypto_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,--version-script=enclave/Enclave.lds \
	$(ENCLAVE_LDFLAGS)

RustEnclave_Name := enclave/enclave.so
Signed_RustEnclave_Name := bin/enclave.signed.so

.PHONY: all
all: $(App_Name) $(Signed_RustEnclave_Name)

######## EDL Objects ########

$(Enclave_EDL_Files): $(SGX_EDGER8R) $(ENCLAVE)/Enclave.edl
	$(SGX_EDGER8R) --trusted $(ENCLAVE)/Enclave.edl --search-path $(SGX_SDK)/include --search-path ../sgx/edl --trusted-dir enclave
	$(SGX_EDGER8R) --untrusted $(ENCLAVE)/Enclave.edl --search-path $(SGX_SDK)/include --search-path ../sgx/edl --untrusted-dir $(APP)
	@echo "GEN  =>  $(Enclave_EDL_Files)"

######## App Objects ########

$(APP)/Enclave_u.o: $(Enclave_EDL_Files)
	@$(CC) $(App_C_Flags) -c $(APP)/Enclave_u.c -o $@
	@echo "CC   <=  $<"

$(App_Enclave_u_Object): $(APP)/Enclave_u.o
	$(AR) rcsD $@ $^
	cp $(App_Enclave_u_Object) ./lib

$(App_Name): $(App_Enclave_u_Object) $(App_SRC_Files)
	@cd $(APP) && SGX_SDK=$(SGX_SDK) cargo build $(App_Rust_Flags)
	@echo "Cargo  =>  $@"
	mkdir -p bin
	cp $(App_Rust_Path)/$(APP) ./bin

######## Enclave Objects ########

enclave/Enclave_t.o: $(Enclave_EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c $(ENCLAVE)/Enclave_t.c -o $@
	@echo "CC   <=  $<"

$(RustEnclave_Name): enclave enclave/Enclave_t.o
	@$(CXX) $(ENCLAVE)/Enclave_t.o -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_RustEnclave_Name): $(RustEnclave_Name)
	mkdir -p bin
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE)/Enclave_private.pem -enclave $(RustEnclave_Name) -out $@ -config $(ENCLAVE)/Enclave.config.xml
	@echo "SIGN =>  $@"

.PHONY: enclave
enclave:
	$(MAKE) -C ./$(ENCLAVE)/


.PHONY: clean
clean:
	@rm -f $(App_Name) $(RustEnclave_Name) $(Signed_RustEnclave_Name) $(ENCLAVE)/*_t.* $(APP)/*_u.* lib/*.a
	@cd enclave && cargo clean && rm -f Cargo.lock
	@cd $(APP) && cargo clean && rm -f Cargo.lock
