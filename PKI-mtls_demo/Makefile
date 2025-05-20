# Variables
CA_DIR       := ca
CA_KEY       := $(CA_DIR)/ca.key.pem
CA_CERT      := $(CA_DIR)/ca.cert.pem
CA_SUBJ      := "/C=TW/ST=Taipei/L=Taipei/O=MyOrg/OU=RootCA/CN=MyRootCA"
CA_DAYS      := 3650

SERVER_DIR   := server
SERVER_KEY   := $(SERVER_DIR)/server.key.pem
SERVER_CSR   := $(SERVER_DIR)/server.csr.pem
SERVER_CERT  := $(SERVER_DIR)/server.cert.pem
SERVER_SUBJ  := "/C=TW/ST=Taipei/L=Taipei/O=MyOrg/OU=WebServer/CN=localhost"
SERVER_DAYS  := 365

CLIENT_DIR   := client
CLIENT_KEY   := $(CLIENT_DIR)/client.key.pem
CLIENT_CSR   := $(CLIENT_DIR)/client.csr.pem
CLIENT_CERT  := $(CLIENT_DIR)/client.cert.pem
CLIENT_P12   := $(CLIENT_DIR)/client.p12
DEVICE_NAME  := MyDevice
P12_PASS     := 
CLIENT_DAYS  := 365

# Default target
.PHONY: all clean npm_server
all: server client export_p12

# 1. Generate Root CA
.PHONY: ca
ca: $(CA_CERT)

$(CA_KEY):
	@mkdir -p $(CA_DIR)
	openssl genrsa -out $(CA_KEY) 4096
	chmod 400 $(CA_KEY)
	@echo "Generated CA private key: $(CA_KEY)"

$(CA_CERT): $(CA_KEY)
	openssl req -x509 -new -nodes \
		-key $(CA_KEY) \
		-sha256 -days $(CA_DAYS) \
		-out $(CA_CERT) \
		-subj $(CA_SUBJ)
	chmod 444 $(CA_CERT)
	@echo "Generated CA certificate: $(CA_CERT)"

# 2. Generate Server Certificate
.PHONY: server
server: $(SERVER_CERT)

$(SERVER_KEY):
	@mkdir -p $(SERVER_DIR)
	openssl genrsa -out $(SERVER_KEY) 2048
	@echo "Generated server private key: $(SERVER_KEY)"

$(SERVER_CSR): $(SERVER_KEY)
	openssl req -new \
		-key $(SERVER_KEY) \
		-out $(SERVER_CSR) \
		-subj $(SERVER_SUBJ)
	@echo "Generated server CSR: $(SERVER_CSR)"

$(SERVER_CERT): $(SERVER_CSR) $(CA_CERT)
	openssl x509 -req \
		-in $(SERVER_CSR) \
		-CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial \
		-out $(SERVER_CERT) \
		-days $(SERVER_DAYS) -sha256
	chmod 444 $(SERVER_CERT)
	@echo "Signed server certificate: $(SERVER_CERT)"

# 3. Generate Client Certificate
.PHONY: client
client: $(CLIENT_CERT)

$(CLIENT_KEY):
	@mkdir -p $(CLIENT_DIR)
	openssl genrsa -out $(CLIENT_KEY) 2048
	@echo "Generated client private key: $(CLIENT_KEY)"

$(CLIENT_CSR): $(CLIENT_KEY)
	openssl req -new \
		-key $(CLIENT_KEY) \
		-out $(CLIENT_CSR) \
		-subj "/C=TW/ST=Taipei/L=Taipei/O=MyOrg/OU=Clients/CN=$(DEVICE_NAME)"
	@echo "Generated client CSR: $(CLIENT_CSR)"

$(CLIENT_CERT): $(CLIENT_CSR) $(CA_CERT)
	openssl x509 -req \
		-in $(CLIENT_CSR) \
		-CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial \
		-out $(CLIENT_CERT) \
		-days $(CLIENT_DAYS) -sha256
	chmod 444 $(CLIENT_CERT)
	@echo "Signed client certificate: $(CLIENT_CERT)"

# 4. Export PKCS#12 bundle for client
.PHONY: export_p12
export_p12: $(CLIENT_P12)

$(CLIENT_P12): $(CLIENT_KEY) $(CLIENT_CERT) $(CA_CERT)
	openssl pkcs12 -export \
		-inkey $(CLIENT_KEY) \
		-in $(CLIENT_CERT) \
		-certfile $(CA_CERT) \
		-out $(CLIENT_P12) \
		-name "$(DEVICE_NAME)" \
		-passout pass:$(P12_PASS)
	@echo "Exported PKCS#12 bundle: $(CLIENT_P12)"

npm_server:
	npm init -y
	npm install express
	npm start

# Clean up all generated files
clean:
	rm -f $(CA_KEY) $(CA_CERT) ca.srl ca.cert.srl
	rm -rf $(SERVER_DIR) $(CLIENT_DIR)
	@echo "Cleaned all generated certificates and keys."
