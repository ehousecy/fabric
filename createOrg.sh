domain=$1
nodeType=$2
caCuve=$3
tlsCuve=$4
nodeIndex=$5

mkdir -p organizations/${nodeType}Organizations/${domain}/ca
mkdir -p organizations/${nodeType}Organizations/${domain}/tlsca
mkdir -p organizations/${nodeType}Organizations/${domain}/msp/admincerts
mkdir -p organizations/${nodeType}Organizations/${domain}/msp/cacerts
mkdir -p organizations/${nodeType}Organizations/${domain}/msp/tlscacerts
mkdir -p organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/msp/admincerts
mkdir -p organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/msp/cacerts
mkdir -p organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/msp/keystore
mkdir -p organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/msp/signcerts
mkdir -p organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/msp/tlscacerts
mkdir -p organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/tls
mkdir -p organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/msp/admincerts
mkdir -p organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/msp/cacerts
mkdir -p organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/msp/keystore
mkdir -p organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/msp/signcerts
mkdir -p organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/msp/tlscacerts
mkdir -p organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/tls

# 1. create root ca
cName=ca.${domain}
openssl ecparam -name ${caCuve} -genkey -out ca-key_.pem
openssl pkcs8 -inform PEM -outform PEM -topk8 -nocrypt -in ca-key_.pem -out ca-key.pem
openssl req -new -key ca-key.pem -out ca-cert-req.csr -subj "/C=US/ST=North Carolina/L=Raleigh/O=${domain}/CN=${cName}"
openssl x509 -req -sha256 -extfile openssl-root.conf -extensions usr_cert  -in ca-cert-req.csr -out ca-cert.pem -signkey ca-key.pem  -CAcreateserial -days 3650

cp ca-cert.pem organizations/${nodeType}Organizations/${domain}/ca/${cName}-cert.pem
cp ca-key.pem organizations/${nodeType}Organizations/${domain}/ca/priv_sk
cp ca-cert.pem organizations/${nodeType}Organizations/${domain}/msp/cacerts/${cName}-cert.pem
cp ca-cert.pem organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/msp/cacerts/${cName}-cert.pem
cp ca-cert.pem organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/msp/cacerts/${cName}-cert.pem

# 2. create admin cert
cName=Admin@${domain}
openssl ecparam -name ${caCuve} -genkey -out admin_sk
openssl pkcs8 -inform PEM -outform PEM -topk8 -nocrypt -in admin_sk -out admin-cert_sk
openssl req -new -key admin-cert_sk -keyform pem -out admin-ca.csr -subj "/C=US/ST=North Carolina/L=Raleigh/OU=admin/CN=${cName}"
openssl x509 -req -sha256 -extfile openssl.conf -extensions usr_cert -in admin-ca.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -days 3650 -out admin-aa.pem

cp admin-aa.pem organizations/${nodeType}Organizations/${domain}/msp/admincerts/${cName}-cert.pem
cp admin-aa.pem organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/msp/admincerts/${cName}-cert.pem
cp admin-aa.pem organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/msp/signcerts/${cName}-cert.pem
cp admin-aa.pem organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/msp/admincerts/${cName}-cert.pem
cp admin_sk organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/msp/keystore/priv_sk

# 3. create node cert
cName=${nodeType}${nodeIndex}.${domain}
openssl ecparam -name ${caCuve} -genkey -out admin_sk
openssl pkcs8 -inform PEM -outform PEM -topk8 -nocrypt -in admin_sk -out admin-cert_sk
openssl req -new -key admin-cert_sk -keyform pem -out admin-ca.csr -subj "/C=US/ST=North Carolina/L=Raleigh/OU=${nodeType}/CN=${cName}"
openssl x509 -req -sha256 -extfile openssl.conf -extensions usr_cert -in admin-ca.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -days 3650 -out admin-aa.pem

cp admin-aa.pem organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/msp/signcerts/${cName}-cert.pem
cp admin_sk organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/msp/keystore/priv_sk


# 4. create root tls ca
cName=tlsca.${domain}
openssl ecparam -name ${tlsCuve} -genkey -out ca-key_.pem
openssl pkcs8 -inform PEM -outform PEM -topk8 -nocrypt -in ca-key_.pem -out ca-key.pem
openssl req -new -key ca-key.pem -out ca-cert-req.csr -subj "/C=US/ST=North Carolina/L=Raleigh/O=${domain}/CN=${cName}"
openssl x509 -req -sha256 -extfile openssl-root.conf -extensions usr_cert  -in ca-cert-req.csr -out ca-cert.pem -signkey ca-key.pem  -CAcreateserial -days 3650

cp ca-cert.pem organizations/${nodeType}Organizations/${domain}/tlsca/${cName}-cert.pem
cp ca-key.pem organizations/${nodeType}Organizations/${domain}/tlsca/priv_sk
cp ca-cert.pem organizations/${nodeType}Organizations/${domain}/msp/tlscacerts/${cName}-cert.pem
cp ca-cert.pem organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/msp/tlscacerts/${cName}-cert.pem
cp ca-cert.pem organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/msp/tlscacerts/${cName}-cert.pem
cp ca-cert.pem organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/tls/ca.crt
cp ca-cert.pem organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/tls/ca.crt

# 5. create admin cert
cName=Admin@${domain}
openssl ecparam -name ${tlsCuve} -genkey -out admin_sk
openssl pkcs8 -inform PEM -outform PEM -topk8 -nocrypt -in admin_sk -out admin-cert_sk
openssl req -new -key admin-cert_sk -keyform pem -out admin-ca.csr -subj "/C=US/ST=North Carolina/L=Raleigh/CN=${cName}"
openssl x509 -req -sha256 -extfile openssl-tls.conf -extensions usr_cert -in admin-ca.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -days 3650 -out admin-aa.pem

cp admin-aa.pem organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/tls/client.crt
cp admin_sk organizations/${nodeType}Organizations/${domain}/users/Admin@${domain}/tls/client.key

# 6. create node cert
cName=${nodeType}${nodeIndex}.${domain}
openssl ecparam -name ${tlsCuve} -genkey -out admin_sk
openssl pkcs8 -inform PEM -outform PEM -topk8 -nocrypt -in admin_sk -out admin-cert_sk
openssl req -new -key admin-cert_sk -keyform pem -out admin-ca.csr -subj "/C=US/ST=North Carolina/L=Raleigh/CN=${cName}"
openssl x509 -req -sha256 -extfile openssl-tls.conf -extensions usr_cert -in admin-ca.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -days 3650 -out admin-aa.pem

cp admin-aa.pem organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/tls/server.crt
cp admin_sk organizations/${nodeType}Organizations/${domain}/${nodeType}s/${nodeType}${nodeIndex}.${domain}/tls/server.key
