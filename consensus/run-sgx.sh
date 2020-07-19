set -e

SAFETY_RULES=safety-rules
ENCLAVE_PATH=safety-rules/sgx

# first build the LSR, which invokes lsr-sgx...
cargo +nightly build -p $SAFETY_RULES

# build enclave
cd $ENCLAVE_PATH
./build.sh
cd -

# test
cargo +nightly x test -p $SAFETY_RULES -- --nocapture
