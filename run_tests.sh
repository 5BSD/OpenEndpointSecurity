#!/bin/sh
# run_tests.sh - Compile and run ESC tests on the VM

set -e

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SYS_DIR=${SYSDIR:-/usr/src/sys}
ACL_LIB=
MODULE="$ROOT_DIR/sys/security/esc/esc.ko"

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

if [ "$(id -u)" -ne 0 ]; then
    echo "${RED}run_tests.sh must be run as root (kldload/kldunload required)${NC}"
    exit 1
fi

for libdir in /lib /usr/lib /usr/local/lib; do
    if [ -e "$libdir/libacl.so" ] || [ -e "$libdir/libacl.a" ]; then
        ACL_LIB="-lacl"
        break
    fi
done

# Build only if we don't already have a module (or if you force it).
if [ "${FORCE_BUILD:-0}" -ne 0 ] || [ ! -f "$MODULE" ]; then
    if [ ! -d "$SYS_DIR" ]; then
        echo "SYSDIR not found: $SYS_DIR"
        echo "Set SYSDIR=/path/to/FreeBSD/src/sys and rerun."
        echo "Or deploy a prebuilt esc.ko to $MODULE and rerun."
        exit 1
    fi

    echo "=== Building ESC module ==="
    make -C "$ROOT_DIR/sys/security/esc" SYSDIR="$SYS_DIR"
fi

cd "$ROOT_DIR"

echo "=== Unloading old module (if loaded) ==="
kldunload esc 2>/dev/null || true

echo "=== Loading ESC module ==="
kldload "$MODULE"
if [ $? -ne 0 ]; then
    printf "${RED}FAILED to load module${NC}\n"
    exit 1
fi

echo "=== Module loaded ==="
kldstat | grep esc
sysctl security.esc

echo "=== Checking /dev/esc ==="
ls -la /dev/esc

echo "=== Compiling test_esc ==="
cc -o test_esc test_esc.c -I"$ROOT_DIR" -I"$ROOT_DIR/sys"
if [ $? -ne 0 ]; then
    printf "${RED}FAILED to compile test_esc${NC}\n"
    exit 1
fi

if [ -d tests ]; then
    echo "=== Building unit tests ==="
    make -C tests CFLAGS="-Wall -Wextra -I$ROOT_DIR/sys" clean all
    if [ $? -ne 0 ]; then
        printf "${RED}FAILED to compile unit tests${NC}\n"
        exit 1
    fi

    echo "=== Running unit tests ==="
    FAILED=0
    PASSED=0
    SKIPPED=0
    FAILED_TESTS=""
    SKIPPED_TESTS=""
    cd tests
    for t in test_*; do
        [ -x "$t" ] || continue
        printf "${BOLD}--- Running $t ---${NC}\n"
        output=$(./"$t" 2>&1) && result=0 || result=$?
        echo "$output"

        # Check for SKIP in output
        if echo "$output" | grep -q "^SKIP:"; then
            SKIPPED=$((SKIPPED + 1))
            SKIPPED_TESTS="$SKIPPED_TESTS $t"
            printf "${YELLOW}SKIPPED${NC}: $t\n"
        elif [ $result -eq 0 ]; then
            PASSED=$((PASSED + 1))
            printf "${GREEN}PASSED${NC}: $t\n"
        else
            FAILED=$((FAILED + 1))
            FAILED_TESTS="$FAILED_TESTS $t"
            printf "${RED}FAILED${NC}: $t\n"
        fi
        echo ""
    done
    cd ..

    echo "=== Test Suite Complete ==="
    printf "Passed:  ${GREEN}$PASSED${NC}\n"
    printf "Skipped: ${YELLOW}$SKIPPED${NC}\n"
    printf "Failed:  ${RED}$FAILED${NC}\n"

    if [ $SKIPPED -gt 0 ]; then
        echo ""
        printf "${YELLOW}Skipped tests (environment limitations):${NC}\n"
        for t in $SKIPPED_TESTS; do
            printf "  ${YELLOW}$t${NC}\n"
        done
    fi

    if [ $FAILED -gt 0 ]; then
        echo ""
        printf "${RED}${BOLD}=== $FAILED TESTS FAILED ===${NC}\n"
        for t in $FAILED_TESTS; do
            printf "  ${RED}$t${NC}\n"
        done
        exit 1
    fi
fi

echo ""
printf "${GREEN}${BOLD}=== All unit tests passed ===${NC}\n"
echo ""
echo "To run interactive event monitor:"
echo "  ./test_esc       - NOTIFY mode (shows argc for exec events)"
echo "  ./test_esc -a    - AUTH mode (retrieves full arguments)"
