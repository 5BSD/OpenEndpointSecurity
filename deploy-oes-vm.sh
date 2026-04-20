#!/bin/sh
#
# Deploy OES kernel module and tests to bhyve VM
#
# Usage:
#   ./deploy-oes-vm.sh [build|deploy|test|all]
#
#   build    - Build module, library, examples, and tests locally
#   deploy   - Copy artifacts to VM via SSH
#   test     - Run test suite on VM via SSH
#   all      - Build, deploy, and test
#

set -e

SRCDIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SYSDIR="/home/koryheard/Projects/5BSD/sys"
VM_NAME="jaildesc-test"
VM_IP="192.168.6.113"
VM_DEST="/tmp/oes"

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

cd "$SRCDIR"

wait_for_vm_ssh() {
    printf "=== Waiting for ${VM_IP} "
    i=0
    while [ "$i" -lt 60 ]; do
        if ssh -o BatchMode=yes -o ConnectTimeout=2 "root@${VM_IP}" true \
            >/dev/null 2>&1; then
            printf " ${GREEN}reachable${NC} ===\n"
            return 0
        fi
        printf "."
        i=$((i + 1))
        sleep 2
    done
    printf "\n${RED}ERROR: VM did not come back${NC}\n"
    exit 1
}

build_all() {
    if [ ! -f "${SYSDIR}/sys/param.h" ]; then
        printf "${RED}ERROR: SYSDIR (${SYSDIR}) missing sys/param.h${NC}\n"
        echo "Set SYSDIR to your 5BSD/sys tree."
        exit 1
    fi

    echo "=== Building OES kernel module (SYSDIR=${SYSDIR}) ==="
    make -C sys/security/oes clean
    make -C sys/security/oes SYSDIR="$SYSDIR"
    echo ""

    echo "=== Building liboes ==="
    make -C lib/liboes clean
    make -C lib/liboes
    echo ""

    echo "=== Building examples ==="
    make -C examples clean
    make -C examples
    echo ""

    echo "=== Building tests ==="
    make -C tests clean
    make -C tests CFLAGS="-Wall -Wextra -I${SRCDIR}/sys"
    echo ""

    printf "${GREEN}=== Build complete ===${NC}\n"
}

deploy_ssh() {
    echo "=== Deploying to ${VM_IP} ==="

    if ! ping -c 1 -t 2 "$VM_IP" >/dev/null 2>&1; then
        printf "${RED}ERROR: VM not reachable at ${VM_IP}${NC}\n"
        echo "Start VM with: doas vm start ${VM_NAME}"
        exit 1
    fi

    # Single tar pipe to avoid per-file SSH handshakes
    echo "  Copying all artifacts via tar..."
    tar cf - \
        sys/security/oes/oes.ko \
        sys/security/oes/oes.h \
        sys/security/oes/oes_internal.h \
        lib/liboes/liboes.so.1 \
        lib/liboes/liboes.a \
        lib/liboes/liboes.h \
        examples/oesd \
        examples/vendor_client \
        examples/oeslogger \
        tests/Makefile \
        tests/test_* \
        run_tests.sh \
        test_oes.c \
        2>/dev/null | \
        ssh "root@${VM_IP}" "mkdir -p ${VM_DEST} && cd ${VM_DEST} && tar xf -"

    # Install shared lib and headers on VM
    echo "  Installing liboes and headers..."
    ssh "root@${VM_IP}" "\
        cp ${VM_DEST}/lib/liboes/liboes.so.1 /usr/local/lib/ && \
        ln -sf liboes.so.1 /usr/local/lib/liboes.so && \
        ldconfig && \
        mkdir -p /usr/local/include/security/oes && \
        cp ${VM_DEST}/sys/security/oes/oes.h /usr/local/include/security/oes/"

    printf "${GREEN}=== Deploy complete ===${NC}\n"
    echo ""
    echo "Run tests:  $0 test"
    echo "SSH:        ssh root@${VM_IP}"
    echo "Manual:     ssh root@${VM_IP} 'cd ${VM_DEST} && ./run_tests.sh'"
    echo "oeslogger:  ssh root@${VM_IP} '${VM_DEST}/examples/oeslogger -p'"
}

run_tests() {
    echo "=== Running OES tests on ${VM_IP} ==="
    echo ""

    # Unload old module if present, load new one, run tests
    ssh -t "root@${VM_IP}" "cd ${VM_DEST} && \
        SYSDIR=/usr/src/sys \
        sh run_tests.sh"

    echo ""
    printf "${GREEN}${BOLD}=== Test run complete ===${NC}\n"
}

start_vm() {
    echo "=== Starting VM ${VM_NAME} ==="
    doas vm start "$VM_NAME"
    wait_for_vm_ssh
}

stop_vm() {
    echo "=== Stopping VM ${VM_NAME} ==="
    ssh "root@${VM_IP}" shutdown -p now || true
    sleep 3
}

show_status() {
    echo "=== VM Status ==="
    doas vm list 2>/dev/null | grep "$VM_NAME" || echo "(vm list requires root)"
    echo ""
    echo "SSH check:"
    if ssh -o BatchMode=yes -o ConnectTimeout=3 "root@${VM_IP}" \
        'echo "  FreeBSD $(freebsd-version)"; kldstat -m oes 2>/dev/null && echo "  OES module: loaded" || echo "  OES module: not loaded"; ls /dev/oes 2>/dev/null && echo "  /dev/oes: present" || echo "  /dev/oes: absent"' 2>/dev/null; then
        :
    else
        echo "  ${RED}Not reachable${NC}"
    fi
}

show_usage() {
    echo "Usage: $0 [build|deploy|test|start|stop|status|all]"
    echo ""
    echo "Commands:"
    echo "  build    - Build module, library, examples, and tests"
    echo "  deploy   - Deploy to VM via SSH (VM must be running)"
    echo "  test     - Run test suite on VM via SSH"
    echo "  start    - Start VM and wait for SSH"
    echo "  stop     - Shutdown VM"
    echo "  status   - Check VM and OES module status"
    echo "  all      - Build, deploy, and test"
    echo ""
    echo "VM: ${VM_NAME} (${VM_IP})"
    echo "Remote dir: ${VM_DEST}"
}

case "${1:-}" in
    build)
        build_all
        ;;
    deploy)
        deploy_ssh
        ;;
    test)
        run_tests
        ;;
    start)
        start_vm
        ;;
    stop)
        stop_vm
        ;;
    status)
        show_status
        ;;
    all)
        build_all
        deploy_ssh
        run_tests
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
