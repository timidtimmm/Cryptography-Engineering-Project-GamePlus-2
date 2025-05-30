# 定義變數以增加彈性
CLIENT_KEY         := client/client.key.pem
CLIENT_CSR         := client/client.csr.pem
CLIENT_CERT        := client/client.cert.pem
CA_KEY             := ca/ca.key.pem
CA_CERT            := ca/ca.cert.pem
CA_SERIAL          := ca/ca.srl
OUTPUT_P12         := client.p12
DEVICE_NAME        := "MyDevice"
PASSWORD           := "your_password"        # 注意：在 Makefile 中儲存密碼並不安全！
SERVER_CERT_SCRIPT := issue_server_cert.py
CLIENT_CERT_SCRIPT := issue_client_cert.py
NPM_SERVER_NAME    := my_server              # 可以自訂伺服器名稱

# .PHONY 標記，確保這些目標即使有同名檔案也會執行
.PHONY: all clean server_certs client_certs npm_server ca_key ca_cert ca_serial client_key client_csr client_cert

all: server_certs client_certs $(OUTPUT_P12) npm_server

ca_key:
	@mkdir -p $(dir $(CA_KEY))
	openssl genrsa -out $(CA_KEY) 4096

ca_cert: ca_key
	@mkdir -p $(dir $(CA_CERT))
	openssl req -x509 -new -nodes \
	    -key    $(CA_KEY) \
	    -sha256 -days 3650 \
	    -out    $(CA_CERT) \
	    -subj   "/C=TW/ST=Taipei/L=Taipei/O=MyOrg/OU=RootCA/CN=MyRootCA"

ca_serial: ca_cert
	@mkdir -p $(dir $(CA_SERIAL))
	@echo "01" > $(CA_SERIAL)
	@echo "Created CA serial file: $(CA_SERIAL)"

client_key:
	@mkdir -p $(dir $(CLIENT_KEY))
	openssl genrsa -out $(CLIENT_KEY) 2048

client_csr: client_key
	@mkdir -p $(dir $(CLIENT_CSR))
	openssl req -new \
	    -key  $(CLIENT_KEY) \
	    -out  $(CLIENT_CSR) \
	    -subj "/C=TW/ST=Taipei/L=Taipei/O=MyOrg/OU=Clients/CN=$(DEVICE_NAME)"

client_cert: ca_cert client_csr
	@mkdir -p $(dir $(CLIENT_CERT))
	openssl x509 -req \
	    -in       $(CLIENT_CSR) \
	    -CA       $(CA_CERT) -CAkey $(CA_KEY) \
	    -CAserial $(CA_SERIAL) \
	    -out      $(CLIENT_CERT) \
	    -days 365 -sha256

server_certs: ca_serial
	@echo "Generating server certificates..."
	python $(SERVER_CERT_SCRIPT)
	@echo "Done!"

client_certs: ca_serial client_cert
	@echo "Generating client certificates..."
	python $(CLIENT_CERT_SCRIPT)
	@echo "Done!"

$(OUTPUT_P12): client_cert ca_cert
	@echo "Creating $(OUTPUT_P12)..."
	openssl pkcs12 -export \
	    -inkey     $(CLIENT_KEY) \
	    -in        $(CLIENT_CERT) \
	    -certfile  $(CA_CERT) \
	    -out       $(OUTPUT_P12) \
	    -name      $(DEVICE_NAME) \
	    -passout   pass:$(PASSWORD)
	@echo "Done!"

npm_server:
	@echo "Setting up npm server in '$(NPM_SERVER_NAME)'..."
	npm init -y
	npm install express
	npm start
	@echo "NPM server is running in directory '$(NPM_SERVER_NAME)'"

clean:
	@echo "Cleaning up..."
	rm -f $(OUTPUT_P12)
	rm -rf $(NPM_SERVER_NAME)
	rm -f $(CA_SERIAL)
	rm -f $(CA_KEY) $(CA_CERT)
	rm -f $(CLIENT_KEY) $(CLIENT_CSR) $(CLIENT_CERT)
	@echo "Done!"
