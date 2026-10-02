#!/usr/bin/env bash
# Start lldap and OpenLDAP in Docker for TestContainerDirectories, seeded with
# the same four people as the live lab:
#
#   alice  silo-users (plus silo-viewers, a groupOfNames group)
#   bob    silo-users, silo-admins
#   carol  no group
#   dave   silo-users (plus silo-posix, a posixGroup group)
#
# Usage:
#   scripts/directory-containers.sh up     start, seed, and write the env file
#   scripts/directory-containers.sh down   remove the containers and work dir
#
# `up` writes $LDAPTEST_DIR/ldaptest.env (KEY=value lines) with the URLs, DNs,
# and generated passwords the test reads; source it before `go test`. TLS uses
# a CA generated here, with a server certificate for LDAPTEST_HOST.
#
# Settings (environment):
#   LDAPTEST_DIR     work dir for the CA, seed files, and env file
#                    (default: .ldaptest in the repository root)
#   LDAPTEST_PREFIX  container name prefix (default: ldaptest-)
#   LDAPTEST_PORTS   first of four consecutive host ports (default: 13890)
#   LDAPTEST_HOST    address the ports are published on and the tests dial;
#                    also in the certificate (default: 127.0.0.1). Set it
#                    with DOCKER_HOST when the containers run on another
#                    machine.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR="${LDAPTEST_DIR:-$PWD/.ldaptest}"
PREFIX="${LDAPTEST_PREFIX:-ldaptest-}"
PORT="${LDAPTEST_PORTS:-13890}"
HOST="${LDAPTEST_HOST:-127.0.0.1}"
LLDAP_IMAGE=lldap/lldap:2026-09-22-alpine
OPENLDAP_IMAGE=osixia/openldap:1.5.0
LLDAP="${PREFIX}lldap"
OPENLDAP="${PREFIX}openldap"
BASE=dc=silo,dc=test

down() {
  docker rm -f "$LLDAP" "$OPENLDAP" >/dev/null 2>&1 || true
  rm -rf "$DIR"
}

# retry <tries> <label> <command...> runs a readiness probe once a second
# until it succeeds. The label names it on timeout; the command may carry a
# password, so it is never printed.
retry() {
  local tries=$1 label=$2
  shift 2
  for _ in $(seq "$tries"); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for $label" >&2
  return 1
}

up() {
  down
  mkdir -p "$DIR/certs" "$DIR/lldap/user-configs" "$DIR/lldap/group-configs"
  chmod 700 "$DIR"
  pw() { openssl rand -hex 16; }
  local alice bob carol dave lldap_admin lldap_bind ol_admin ol_readonly
  alice=$(pw) bob=$(pw) carol=$(pw) dave=$(pw)
  lldap_admin=$(pw) lldap_bind=$(pw) ol_admin=$(pw) ol_readonly=$(pw)

  # CA and server certificate. The key is PKCS#8, which both servers read.
  (
    cd "$DIR/certs"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=ldaptest CA" \
      -keyout ca.key -out ca.pem 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
      -keyout server.key -out server.csr 2>/dev/null
    san="IP:127.0.0.1,DNS:localhost"
    if [ "$HOST" != 127.0.0.1 ]; then
      if [[ "$HOST" =~ ^[0-9.]+$ ]]; then san="$san,IP:$HOST"; else san="$san,DNS:$HOST"; fi
    fi
    printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$san" > ext.cnf
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
      -days 2 -extfile ext.cnf -out server.crt 2>/dev/null
    cat server.crt ca.pem > server-chain.pem
    # osixia generates DH parameters at startup unless given some. Use the
    # fixed RFC 7919 ffdhe2048 group: `openssl dhparam -dsaparam` on
    # OpenSSL 3 writes X9.42 parameters, which slapd's GnuTLS rejects.
    cat > dhparam.pem <<'DHPARAM'
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
DHPARAM
    chmod 644 ./*
  )

  # lldap: people and groups come from the image's bootstrap script.
  local name first groups
  : > "$DIR/lldap/user-configs/users.json"
  for spec in "alice:Alice:silo-users" "bob:Bob:silo-users,silo-admins" "carol:Carol:" "dave:Dave:silo-users"; do
    IFS=: read -r name first groups <<< "$spec"
    printf '{"id":"%s","email":"%s@example.com","password":"%s","displayName":"%s Tester","firstName":"%s","lastName":"Tester","groups":[%s]}\n' \
      "$name" "$name" "${!name}" "$first" "$first" \
      "$(if [ -n "$groups" ]; then echo "\"${groups//,/\",\"}\""; fi)" >> "$DIR/lldap/user-configs/users.json"
  done
  printf '{"id":"silo-bind","email":"silo-bind@example.com","password":"%s","displayName":"Silo bind","groups":["lldap_strict_readonly"]}\n' \
    "$lldap_bind" >> "$DIR/lldap/user-configs/users.json"
  printf '{"name":"silo-users"}\n{"name":"silo-admins"}\n' > "$DIR/lldap/group-configs/groups.json"
  chmod 644 "$DIR/lldap"/*/*.json

  # Files go in with docker cp rather than bind mounts, so the script also
  # works when the Docker daemon cannot see this directory (colima, remote
  # hosts).
  docker create --name "$LLDAP" \
    -p "$HOST:$PORT:3890" -p "$HOST:$((PORT + 1)):6360" \
    -e LLDAP_JWT_SECRET="$(pw)" -e LLDAP_KEY_SEED="$(pw)" \
    -e LLDAP_LDAP_BASE_DN="$BASE" -e LLDAP_LDAP_USER_PASS="$lldap_admin" \
    -e LLDAP_LDAPS_OPTIONS__ENABLED=true \
    -e LLDAP_LDAPS_OPTIONS__CERT_FILE=/certs/server-chain.pem \
    -e LLDAP_LDAPS_OPTIONS__KEY_FILE=/certs/server.key \
    -e LLDAP_URL=http://localhost:17170 -e LLDAP_ADMIN_USERNAME=admin \
    -e LLDAP_ADMIN_PASSWORD="$lldap_admin" \
    "$LLDAP_IMAGE" >/dev/null
  docker cp "$DIR/certs" "$LLDAP:/certs"
  docker cp "$DIR/lldap" "$LLDAP:/bootstrap"
  docker start "$LLDAP" >/dev/null

  docker create --name "$OPENLDAP" \
    -p "$HOST:$((PORT + 2)):389" -p "$HOST:$((PORT + 3)):636" \
    -e LDAP_ORGANISATION="Silo test" -e LDAP_DOMAIN=silo.test \
    -e LDAP_ADMIN_PASSWORD="$ol_admin" -e LDAP_CONFIG_PASSWORD="$ol_admin" \
    -e LDAP_READONLY_USER=true -e LDAP_READONLY_USER_USERNAME=readonly \
    -e LDAP_READONLY_USER_PASSWORD="$ol_readonly" \
    -e LDAP_TLS_CRT_FILENAME=server.crt -e LDAP_TLS_KEY_FILENAME=server.key \
    -e LDAP_TLS_CA_CRT_FILENAME=ca.pem -e LDAP_TLS_DH_PARAM_FILENAME=dhparam.pem \
    -e LDAP_TLS_VERIFY_CLIENT=never \
    "$OPENLDAP_IMAGE" --copy-service >/dev/null
  docker cp "$DIR/certs/." "$OPENLDAP:/container/service/slapd/assets/certs/"
  docker start "$OPENLDAP" >/dev/null

  retry 90 "lldap bootstrap" docker exec "$LLDAP" /app/bootstrap.sh
  retry 90 "OpenLDAP" docker exec "$OPENLDAP" ldapsearch -x -H ldap://localhost -D "cn=admin,$BASE" -w "$ol_admin" -b "$BASE" -s base

  # OpenLDAP: the memberOf overlay tracks groupOfUniqueNames. silo-viewers
  # (groupOfNames) and silo-posix (posixGroup) are found only by a group
  # search, which covers the rest of the OpenLDAP preset's group filter.
  docker exec -i "$OPENLDAP" ldapadd -x -H ldap://localhost -D "cn=admin,$BASE" -w "$ol_admin" >/dev/null <<EOF
dn: ou=people,$BASE
objectClass: organizationalUnit
ou: people

dn: ou=groups,$BASE
objectClass: organizationalUnit
ou: groups

$(for spec in alice:Alice bob:Bob carol:Carol dave:Dave; do
  IFS=: read -r name first <<< "$spec"
  printf 'dn: uid=%s,ou=people,%s\nobjectClass: inetOrgPerson\nuid: %s\ncn: %s Tester\nsn: Tester\ndisplayName: %s Tester\nmail: %s@example.com\n\n' \
    "$name" "$BASE" "$name" "$first" "$first" "$name"
done)

dn: cn=silo-users,ou=groups,$BASE
objectClass: groupOfUniqueNames
cn: silo-users
uniqueMember: uid=alice,ou=people,$BASE
uniqueMember: uid=bob,ou=people,$BASE
uniqueMember: uid=dave,ou=people,$BASE

dn: cn=silo-admins,ou=groups,$BASE
objectClass: groupOfUniqueNames
cn: silo-admins
uniqueMember: uid=bob,ou=people,$BASE

dn: cn=silo-viewers,ou=groups,$BASE
objectClass: groupOfNames
cn: silo-viewers
member: uid=alice,ou=people,$BASE

dn: cn=silo-posix,ou=groups,$BASE
objectClass: posixGroup
cn: silo-posix
gidNumber: 5000
memberUid: dave
EOF
  for name in alice bob carol dave; do
    docker exec "$OPENLDAP" ldappasswd -x -H ldap://localhost -D "cn=admin,$BASE" -w "$ol_admin" \
      -s "${!name}" "uid=$name,ou=people,$BASE" >/dev/null
  done

  umask 077
  cat > "$DIR/ldaptest.env" <<EOF
LDAPTEST=1
LDAPTEST_CA_FILE=$DIR/certs/ca.pem
LDAPTEST_ALICE_PASSWORD=$alice
LDAPTEST_BOB_PASSWORD=$bob
LDAPTEST_CAROL_PASSWORD=$carol
LDAPTEST_DAVE_PASSWORD=$dave
LDAPTEST_LLDAP_URL=ldap://$HOST:$PORT
LDAPTEST_LLDAP_LDAPS_URL=ldaps://$HOST:$((PORT + 1))
LDAPTEST_LLDAP_BIND_DN=uid=silo-bind,ou=people,$BASE
LDAPTEST_LLDAP_BIND_PASSWORD=$lldap_bind
LDAPTEST_LLDAP_USER_BASE_DN=ou=people,$BASE
LDAPTEST_LLDAP_GROUP_BASE_DN=ou=groups,$BASE
LDAPTEST_OPENLDAP_URL=ldap://$HOST:$((PORT + 2))
LDAPTEST_OPENLDAP_LDAPS_URL=ldaps://$HOST:$((PORT + 3))
LDAPTEST_OPENLDAP_BIND_DN=cn=readonly,$BASE
LDAPTEST_OPENLDAP_BIND_PASSWORD=$ol_readonly
LDAPTEST_OPENLDAP_USER_BASE_DN=ou=people,$BASE
LDAPTEST_OPENLDAP_GROUP_BASE_DN=ou=groups,$BASE
EOF
  echo "$DIR/ldaptest.env"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
