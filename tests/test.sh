#!/bin/bash

CERT_TOOL=${CERT_TOOL:-"./bin/cert-tool"}
OPENSSL=${OPENSSL:-"openssl"}
WORK_DIR=${WORK_DIR:-"$(mktemp -d)"}

set -e
set -x

function prepare() {
    echo "Work Dir: ${WORK_DIR}"
    mkdir -p "${WORK_DIR}"
}

function test_gen_rsa_key() {
    local test_key
    local bits=$1

    echo "Generate a RSA ${bits} private key"
    test_key="${WORK_DIR}/rsa_${bits}.key"
    ${CERT_TOOL} key -f -o "${test_key}" --algo rsa --bits "${bits}"
    ${OPENSSL} rsa -in "${test_key}" -check -text | grep "Private-Key:" | grep -q "${bits} bit"
}

function test_gen_ecdsa_key() {
    local test_key
    local bits=$1

    echo "Generate a ECDSA P-${bits} private key"
    test_key="${WORK_DIR}/ec_${bits}.key"
    ${CERT_TOOL} key -f -o "${test_key}" --algo ec --bits "${bits}"
    ${OPENSSL} ec -in "${test_key}" -check -text | grep "Private-Key:" | grep -q "${bits} bit"
}


function test_key() {
    local test_key
    echo "Testing Key"

    test_gen_rsa_key 1024
    test_gen_rsa_key 2048
    test_gen_rsa_key 4096

    test_gen_ecdsa_key 224
    test_gen_ecdsa_key 256
    test_gen_ecdsa_key 384
    test_gen_ecdsa_key 521
}

function fmt_time() {
    local t=$1
    if [[ "$OSTYPE" == darwin* ]]; then
        date -j -u -f "%Y-%m-%d %H:%M:%SZ" "${t}" "+%s"
    else
        date -d "${t}" "+%s"
    fi
}

function test_ca() {
    echo "Testing CA"

    ${CERT_TOOL} key -f -o "${WORK_DIR}/ca.key"

    local now
    now=$(date "+%s")
    ${CERT_TOOL} ca -f -o "${WORK_DIR}/ca.crt" --key "${WORK_DIR}/ca.key" --name "test-ca" --days 1
    ${OPENSSL} x509 -in "${WORK_DIR}/ca.crt" -subject -noout | grep 'CN' | grep -q "test-ca"
    ${OPENSSL} x509 -in "${WORK_DIR}/ca.crt" -issuer -noout | grep 'CN' | grep -q "test-ca"
    ${OPENSSL} x509 -in "${WORK_DIR}/ca.crt" -text | grep "CA:TRUE"
    ${OPENSSL} x509 -in "${WORK_DIR}/ca.crt" -text | grep "Digital Signature, Key Encipherment, Certificate Sign"
    ${OPENSSL} x509 -in "${WORK_DIR}/ca.crt" -text | grep "DNS:test-ca"

    local start_time end_time start_diff end_diff
    start_time=$(${OPENSSL} x509 -in "${WORK_DIR}/ca.crt" -noout -startdate -dateopt iso_8601 | cut -d= -f2)
    start_time=$(fmt_time "${start_time}")
    end_time=$(${OPENSSL} x509 -in "${WORK_DIR}/ca.crt" -noout -enddate -dateopt iso_8601 | cut -d= -f2)
    end_time=$(fmt_time "${end_time}")

    start_diff=$(("${now}" - "${start_time}"))
    end_diff=$(("${end_time}" - "${now}"))

    if [[ "${start_diff}" -gt $((5 * 60)) ]] && [[ "${start_diff}" -lt $((4 * 60)) ]]; then
        echo "CA start time is invalid"
        return 1
    fi

    if [[ "${end_diff}" -lt $((24 * 60 * 60 + 5 * 60)) ]] && [[ "${end_diff}" -gt $((24 * 60 * 60 + 6 * 60)) ]]; then
        echo "CA end time is invalid"
        return 1
    fi
}

function test_cert() {
    echo "Testing Cert"

    ${CERT_TOOL} key -f -o "${WORK_DIR}/ca.key"
    ${CERT_TOOL} ca -f -o "${WORK_DIR}/ca.crt" --key "${WORK_DIR}/ca.key" --name "test-ca" --days 1

    local now
    now=$(date "+%s")
    ${CERT_TOOL} key -o "${WORK_DIR}/cert.key"
    ${CERT_TOOL} cert -o "${WORK_DIR}/cert.crt" --key "${WORK_DIR}/cert.key" \
        --ca-cert "${WORK_DIR}/ca.crt" --ca-key "${WORK_DIR}/ca.key" \
        --name "test-cert" --orgs "org1" --orgs "org2" --days 1 --server --client \
        --names "127.0.0.1" --names "::1" --names "localhost" \
        --time-toleration 10m

    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -subject -noout | grep 'CN' | grep -q "test-cert"
    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -subject -noout | grep 'O' | grep -q "org1"
    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -subject -noout | grep 'O' | grep -q "org2"
    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -issuer -noout | grep 'CN' | grep -q "test-ca"
    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -text | grep "CA:FALSE"
    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -text | grep "Digital Signature, Key Encipherment"
    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -text | grep "TLS Web Server Authentication"
    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -text | grep "TLS Web Client Authentication"
    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -text | grep "DNS:test-cert"
    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -text | grep "DNS:localhost"
    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -text | grep "IP Address:127.0.0.1"
    ${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -text | grep "IP Address:0:0:0:0:0:0:0:1"

    local start_time end_time start_diff end_diff
    start_time=$(${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -noout -startdate -dateopt iso_8601 | cut -d= -f2)
    start_time=$(fmt_time "${start_time}")
    end_time=$(${OPENSSL} x509 -in "${WORK_DIR}/cert.crt" -noout -enddate -dateopt iso_8601 | cut -d= -f2)
    end_time=$(fmt_time "${end_time}")

    start_diff=$(("${now}" - "${start_time}"))
    end_diff=$(("${end_time}" - "${now}"))

    if [[ "${start_diff}" -gt $((10 * 60)) ]] && [[ "${start_diff}" -lt $((9 * 60)) ]]; then
        echo "Cert start time is invalid"
        return 1
    fi

    if [[ "${end_diff}" -lt $((24 * 60 * 60 + 10 * 60)) ]] && [[ "${end_diff}" -gt $((24 * 60 * 60 + 11 * 60)) ]]; then
        echo "Cert end time is invalid"
        return 1
    fi
}

function test_kubeconfig() {
    echo "Testing Kubeconfig"
    local server="https://127.0.0.1"
    local cluster="test-cluster"
    local user="test-user"

    ${CERT_TOOL} key -f -o "${WORK_DIR}/ca.key" --algo ec --bits 521
    ${CERT_TOOL} ca -f -o "${WORK_DIR}/ca.crt" --key "${WORK_DIR}/ca.key" --name "test-ca" --days 2

    local now
    now=$(date "+%s")
    ${CERT_TOOL} kubeconfig -o "${WORK_DIR}/kubeconfig" \
        --ca-cert "${WORK_DIR}/ca.crt" --ca-key "${WORK_DIR}/ca.key" \
        --user "${user}" --cluster "${cluster}" --server "${server}" \
        --algo rsa --bits 2048 --days 2 \
        --name "test-kubeconfig" --orgs "org3" \
        --time-toleration 10m

    grep 'name:' "${WORK_DIR}/kubeconfig" | grep -q "test-user"
    grep 'name:' "${WORK_DIR}/kubeconfig" | grep -q "test-cluster"

    if [[ $(grep 'server:' "${WORK_DIR}/kubeconfig" | awk '{print $2}') != "${server}" ]]; then
        echo "Kubeconfig server is invalid"
        return 1
    fi

    if [[ $(grep 'current-context:' "${WORK_DIR}/kubeconfig" | awk '{print $2}') != "${user}@${cluster}" ]]; then
        echo "Kubeconfig context is invalid"
        return 1
    fi

    local cert key
    cert=$(grep 'client-certificate-data:' "${WORK_DIR}/kubeconfig" | awk '{print $2}' | base64 -d)
    key=$(grep 'client-key-data:' "${WORK_DIR}/kubeconfig" | awk '{print $2}' | base64 -d)

    echo "${key}" | ${OPENSSL} rsa -check -text | grep "Private-Key:" | grep -q "2048 bit"

    echo "${cert}" | ${OPENSSL} x509 -subject -noout | grep 'CN' | grep -q "test-kubeconfig"
    echo "${cert}" | ${OPENSSL} x509 -subject -noout | grep 'O' | grep -q "org3"
    echo "${cert}" | ${OPENSSL} x509 -issuer -noout | grep 'CN' | grep -q "test-ca"
    echo "${cert}" | ${OPENSSL} x509 -text | grep "CA:FALSE"
    echo "${cert}" | ${OPENSSL} x509 -text | grep "Digital Signature, Key Encipherment"
    echo "${cert}" | ${OPENSSL} x509 -text | grep "TLS Web Client Authentication"

    local start_time end_time start_diff end_diff
    start_time=$(echo "${cert}" | ${OPENSSL} x509 -noout -startdate -dateopt iso_8601 | cut -d= -f2)
    start_time=$(fmt_time "${start_time}")
    end_time=$(echo "${cert}" | ${OPENSSL} x509  -noout -enddate -dateopt iso_8601 | cut -d= -f2)
    end_time=$(fmt_time "${end_time}")

    start_diff=$(("${now}" - "${start_time}"))
    end_diff=$(("${end_time}" - "${now}"))

    if [[ "${start_diff}" -gt $((10 * 60)) ]] && [[ "${start_diff}" -lt $((9 * 60)) ]]; then
        echo "Client Cert start time is invalid"
        return 1
    fi

    if [[ "${end_diff}" -lt $((48 * 60 * 60 + 10 * 60)) ]] && [[ "${end_diff}" -gt $((48 * 60 * 60 + 11 * 60)) ]]; then
        echo "Client Cert end time is invalid"
        return 1
    fi

    ${CERT_TOOL} key -f -o "${WORK_DIR}/cert.pem" --algo ec --bits 521
    ${CERT_TOOL} cert -f -o "${WORK_DIR}/cert.pem" --key "${WORK_DIR}/cert.pem" \
        --ca-cert "${WORK_DIR}/ca.crt" --ca-key "${WORK_DIR}/ca.key" \
        --name "test-kubeconfig-2" --days 2 --client \
        --time-toleration 10m

    ${CERT_TOOL} kubeconfig -f -o "${WORK_DIR}/kubeconfig" \
        --ca-cert "${WORK_DIR}/ca.crt" \
        --user "${user}" --cluster "${cluster}" --server "${server}" \
        --cert "${WORK_DIR}/cert.pem" --key "${WORK_DIR}/cert.pem"

    grep 'name:' "${WORK_DIR}/kubeconfig" | grep -q "test-user"
    grep 'name:' "${WORK_DIR}/kubeconfig" | grep -q "test-cluster"

    if [[ $(grep 'server:' "${WORK_DIR}/kubeconfig" | awk '{print $2}') != "${server}" ]]; then
        echo "Kubeconfig server is invalid"
        return 1
    fi

    if [[ $(grep 'current-context:' "${WORK_DIR}/kubeconfig" | awk '{print $2}') != "${user}@${cluster}" ]]; then
        echo "Kubeconfig context is invalid"
        return 1
    fi

    if [ "$(grep 'client-certificate:' "${WORK_DIR}/kubeconfig" | awk '{print $2}')" != "${WORK_DIR}/cert.pem" ]; then
        echo "Kubeconfig client-certificate is invalid"
        return 1
    fi

    if [ "$(grep 'client-key:' "${WORK_DIR}/kubeconfig" | awk '{print $2}')" != "${WORK_DIR}/cert.pem" ]; then
        echo "Kubeconfig client-key is invalid"
        return 1
    fi
}

function test_check() {
    echo "Testing Check"

    local server="https://127.0.0.1"

    ${CERT_TOOL} key -f -o "${WORK_DIR}/key.pem" --algo ec --bits 521
    ${CERT_TOOL} ca -f -o "${WORK_DIR}/ca.crt" --key "${WORK_DIR}/key.pem" --name "test-ca" --days 2

    ${CERT_TOOL} cert -f -o "${WORK_DIR}/cert.crt" --key "${WORK_DIR}/key.pem" \
        --ca-cert "${WORK_DIR}/ca.crt" --ca-key "${WORK_DIR}/key.pem" \
        --name "test-check" --days 2 --server \
        --time-toleration 0s

    ${CERT_TOOL} cert -f -o "${WORK_DIR}/key.pem" --key "${WORK_DIR}/key.pem" \
        --ca-cert "${WORK_DIR}/ca.crt" --ca-key "${WORK_DIR}/key.pem" \
        --name "test-check-2" --days 2 --client \
        --time-toleration 0s

    ${CERT_TOOL} kubeconfig -f -o "${WORK_DIR}/kubeconfig-check-1" \
        --ca-cert "${WORK_DIR}/ca.crt" --ca-key "${WORK_DIR}/key.pem" \
        --server "${server}" \
        --algo ec --bits 384 --days 2 \
        --name "test-kubeconfig-3" --orgs "org3" \
        --time-toleration 0s

    ${CERT_TOOL} kubeconfig -f -o "${WORK_DIR}/kubeconfig-check-2" \
        --ca-cert "${WORK_DIR}/ca.crt" \
        --server "${server}" \
        --cert "${WORK_DIR}/key.pem" --key "${WORK_DIR}/key.pem"

    ${CERT_TOOL} check-expiry "${WORK_DIR}/ca.crt" "${WORK_DIR}/key.pem" "${WORK_DIR}/kubeconfig-check-1" "${WORK_DIR}/kubeconfig-check-2"

    local i
    for i in "${WORK_DIR}/ca.crt" "${WORK_DIR}/key.pem" "${WORK_DIR}/cert.crt" "${WORK_DIR}/kubeconfig-check-1" "${WORK_DIR}/kubeconfig-check-2"; do
        if ${CERT_TOOL} check-expiry "${i}" --days-before 3; then
            echo "Check expiry alter-before failed"
            return 1
        fi
    done

}

function clean_up() {
    rm -rf "${WORK_DIR}"
}

function test_main() {
    prepare
    test_key
    test_ca
    test_cert
    test_kubeconfig
    test_check
    clean_up
}

test_main