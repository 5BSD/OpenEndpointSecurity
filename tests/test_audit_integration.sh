#!/bin/sh
#
# ESC Audit Integration Verification Script
#
# This script demonstrates how to verify that ESC audit records are being
# generated for authorization denials. Run with root privileges.
#
# Prerequisites:
#   - ESC module loaded
#   - Audit daemon running (auditd)
#   - Appropriate audit policy configured
#
# Usage: sudo ./test_audit_integration.sh
#

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

if ! kldstat -q -m esc 2>/dev/null; then
    echo "ESC module is not loaded. Load it first:"
    echo "  kldload /path/to/esc.ko"
    exit 1
fi

TESTDIR="$(dirname "$0")"

echo "=== ESC Audit Integration Verification ==="
echo ""

# Check if audit daemon is running
if ! pgrep -q auditd; then
    echo "WARNING: auditd is not running."
    echo "Audit records will not be written to the audit trail."
    echo ""
    echo "To enable auditing:"
    echo "  1. Edit /etc/security/audit_control"
    echo "  2. service auditd start"
    echo ""
fi

echo "ESC generates audit records when authorization is denied."
echo "The audit record includes the text 'ESC: authorization denied'"
echo ""
echo "To verify audit integration:"
echo ""
echo "1. Enable auditing (if not already enabled):"
echo "   service auditd start"
echo ""
echo "2. Run the AUTH deny test to generate denials:"
echo "   ${TESTDIR}/test_auth_responses"
echo ""
echo "3. Check the audit trail for ESC records:"
echo "   praudit /var/audit/current | grep -i esc"
echo ""
echo "4. Or search the audit trail:"
echo "   auditreduce -m text /var/audit/current | praudit | grep ESC"
echo ""

# If test binary exists, offer to run it
if [ -x "${TESTDIR}/test_auth_responses" ]; then
    echo "Would you like to run the AUTH response test now? (y/n)"
    read -r answer
    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        echo ""
        echo "Running test_auth_responses..."
        "${TESTDIR}/test_auth_responses"
        echo ""
        echo "Test complete. Check audit trail with:"
        echo "  praudit /var/audit/current | grep -i esc"
    fi
fi
