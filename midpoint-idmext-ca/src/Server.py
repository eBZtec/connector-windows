import zmq
import json
import logging
import datetime

from configparser import ConfigParser
from DatabaseManager import DatabaseManager

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

logging.basicConfig(
    filename='/midpoint-idmext-ca/midpoint-idmext-ca-server.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

def decrypt_config():
        secret = '/midpoint-idmext-ca/configuration/secret.key'
        config_file = '/midpoint-idmext-ca/configuration/encrypted_config.ini'

        try:
            with open(secret, 'rb') as key_file:
                key = key_file.read()
            fernet = Fernet(key)

            with open(config_file, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            
            return decrypted_data.decode('utf-8')
        
        except FileNotFoundError as e:
            logging.info(f"Error: The file {e.filename} was not found.")
        except PermissionError as e:
            logging.info(f"Error: You do not have permission to open file {e.filename}")
        except Exception as e:
            logging.info(f"An unexpected error occurred: {e}")

def parse_config(config, section):
    if section in config:
        return {key: config[section][key] for key in config[section]}

class Server:
    def __init__(self):
        configParser = ConfigParser()
        configParser.read_string(decrypt_config())
        self.server_config = parse_config(configParser, 'server')

        self.db = DatabaseManager()
        self.retry_connection()
        
        # Load certificates after successful connection
        self.load_initial_certificates()
        
    def retry_connection(self, retries=5):
        """Retry database connection if it fails."""
        for attempt in range(retries):
            try:
                self.db.connect()
                logging.info("Database connection established.")
                return
            except ConnectionError:
                logging.warning(f"Retrying database connection ({attempt + 1}/{retries})...")
        raise RuntimeError("Failed to establish a database connection after retries.")

    def load_initial_certificates(self):
        """Load and insert initial certificates."""
        try:
            with open(self.server_config.get('mid_cert_file'), "rb") as cert_file:
                self.parseCertificateAndInsert(cert_file.read())
            with open(self.server_config.get('ca_cert_file'), "rb") as cert_file:
                self.parseCertificateAndInsert(cert_file.read())
        except Exception as e:
            logging.error(f"Failed to load initial certificates: {e}")
        
    def load_midpoint_certificate(self):
        """! Loads the midpoint certificate from database.
        @return  midPoint certificate.
        """
        return self.db.get_certificate("MIDPOINT_IDMEXT")['certificate']

    def load_user_certificate(self, username):
        """! Loads a user's certificate from database by his Windows username.
        @param username   The Windows username to search in database.
        @return  The Windows user certificate.
        """
        return self.db.get_certificate(username)['certificate']

    def load_ca_certificate(self, args=[]):
        """! Loads the CA certificate from database.
        @param args Optional argument. If 'pem' returns in PEM format, otherwise, returns raw certificate.
        @return The certification authority certificate in the specified format or None if not found.
        @exception Logs an info message if the CA certificate was not found or another exception occurs. 
        """
        try:
            CA_IDMEXT = self.db.get_certificate("CA_IDMEXT")['certificate']
            if args == 'pem':
                return x509.load_pem_x509_certificate(CA_IDMEXT.encode(), backend=default_backend())
            else:
                return CA_IDMEXT
        except Exception as e:
            logging.info(f"CA certificate not found: {e}")
            return None

    def load_ca_private_key(self):
        """! Loads from file the certification authority private key
        @return The CA private key.
        """
        CA_KEY_PATH = self.server_config.get('ca_key_path')
        with open(CA_KEY_PATH, "rb") as key_file:
            ca_private_key = load_pem_private_key(
                key_file.read(),
                password=self.server_config.get('ca_key_pass').encode(),
                backend=default_backend())
        return ca_private_key

    def sign_csr(self, csr_str):
        """! Sign the received CSR with CA certificate and CA private key.
        @param csr_str Certification signing request from windows user.
        @return Certificate public bytes.
        @exception Logs an info message if the CSR is invalid. 
        """
        try:
            csr = x509.load_pem_x509_csr(csr_str.encode(), default_backend())
        except Exception as e:
            logging.info(f"Received an invalid CSR: {e}")
            return None

        builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self.load_ca_certificate('pem').subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)  # 1 year validity
        )
        certificate = builder.sign(
            private_key=self.load_ca_private_key(),
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        logging.info(f"{csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value} certificate successfully signed")
        return certificate.public_bytes(serialization.Encoding.PEM)

    def parseCertificateAndInsert(self, cert_data):
        """! Parse the certificate and insert in database. If FQDN already exists, update database with new value, otherwise, insert new row.
        @param cert_data Certificate public bytes for parsing an insertion in database.
        @return Certificate raw data.
        @exception Logs an info message if insertion goes wrong or another exception occurs.  
        """
        cert = x509.load_pem_x509_certificate(cert_data)
        fqdn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        cert_string = cert_data.decode() 
        pubkey = cert.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        date = cert.not_valid_after.date()

        try:
            if self.db.exists_row(fqdn):
                self.db.update_row(fqdn, cert_string, pubkey, date)
                logging.info(f"{fqdn} certificate updated in database.")
            else:
                self.db.insert_row(fqdn, cert_string, pubkey, date)
                logging.info(f"{fqdn} certificate inserted in database.")
            return cert_string

        except Exception as e:
            logging.info(f"An error occurred while inserting certificate in postgres: {e}")

    def processRequests(self, request):
        """! Processes certificate-related requests.
        @param request JSON object containing the request details. The request must include an 'action' key and may include additional data.
        @return JSON string containing the result of the request. The JSON includes a 'status' key ()'success' or 'error') and additional data.
        @exception Logs an info message and returns an error as JSON if an exception occurs during processing or if an unknown action is specified.
        """
        
        def handle_request_ca_certificate():   
            try:
                data = self.load_ca_certificate()
                logging.info(f"CA certificate requested")
                return json.dumps({
                    "status": "success",
                    "data": data
                })

            except Exception as e:
                return json.dumps({
                    "status": "erro",
                    "message": f"CA certificate not found in database: {e}"
                })

        def handle_request_midpoint_certificate():
            try:
                data = self.load_midpoint_certificate()
                logging.info(f"Connector certificate requested")

                return json.dumps({
                    "status": "success",
                    "data": data
                })
            except Exception as e:
                return json.dumps({
                    "status": "erro",
                    "message": "Connector certificate not found in database"
                })

        def handle_request_user_certificate():
            try:
                username = request['data']
                certificate = self.load_user_certificate(username)
                logging.info(f"{username} certificate requested by connector")
                return json.dumps({
                    "status": "success",
                    "data": certificate
                })
            except Exception as e:
                return json.dumps({
                    "status": "erro",
                    "message": "User certificate not found in database"
                })

        def handle_request_signed_certificate():
            try:
                signed_cert = self.sign_csr(request['csr'])
                cert_string = self.parseCertificateAndInsert(signed_cert)
                return json.dumps({
                    "status": "success",
                    "data": cert_string
                })
            except Exception as e:
                return json.dumps({
                    "status": "erro",
                    "message": "Invalid CSR: it's not possible to get signed certificate"
                })

        def handle_secret_password_request():
            try:
                hostname = request.get('hostname')
                with open('/midpoint-idmext-ca/configuration/passwords.json', 'r') as f:
                    passwords = json.load(f)
                entry = passwords.get(hostname)
                if entry:
                    logging.info(f"Secret ID and password requested for {hostname}")
                    return json.dumps({
                        "status": "success",
                        "resource_id": entry.get("RESOURCE_ID", ""),
                        "resource_secret": entry.get("RESOURCE_SECRET", "")
                    })
                else:
                    logging.warning(f"Hostname {hostname} not found in passwords.json")
                    return json.dumps({
                        "status": "error",
                        "message": "Hostname not found"
                    })
            except Exception as e:
                return json.dumps({
                    "status": "error",
                    "message": f"Failed to load secret: {e}"
                })


        action_map = {
            'REQUEST_CA_IDMEXT': handle_request_ca_certificate,
            'REQUEST_MIDPOINT_IDMEXT': handle_request_midpoint_certificate,
            'REQUEST_USER_CERTIFICATE': handle_request_user_certificate,
            'REQUEST_SIGNED_CERTIFICATE': handle_request_signed_certificate,
            'REQUEST_SECRET_PASSWORD': handle_secret_password_request
        }
        try:
            action = request.get('action')
            if action in action_map:
                return action_map[action]()
            else:
                raise Exception("Action not found")
        except Exception as e:
            return json.dumps({
                "status": "erro",
                "message": str(e)
            })

    def zmqClient(self):
        context = zmq.Context()
        socket = context.socket(zmq.REP)

        port = self.server_config.get('port')
        socket.bind(f"tcp://*:{port}")
        logging.info(f"ZeroMQ initiated on port {port}")
        
        while True:
            try:
                message = socket.recv()
                if isinstance(json.loads(message), dict):
                    response = self.processRequests(json.loads(message))
                else:
                    response = json.dumps({"status":"success","message":message})
                socket.send_string(response)

            except Exception as e:
                logging.info(f"An error occurred: {e}")
                try:
                    socket.send_string(json.dumps({"status":"erro","message":{e}}))
                except zmq.erro.ZMQerro as send_erro:
                    logging.info(f"Failed to send error response: {send_erro}")

if __name__ == "__main__":
    server = Server()
    server.zmqClient()
