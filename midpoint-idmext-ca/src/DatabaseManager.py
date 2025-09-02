import psycopg2
from configparser import ConfigParser
from cryptography.fernet import Fernet
import logging

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

class DatabaseManager:
    def __init__(self):
        configParser = ConfigParser()
        configParser.read_string(decrypt_config())
        self.db_config = parse_config(configParser, 'postgresql')

    def connect(self):
        """Establish a connection to the PostgreSQL server and create a cursor."""
        try:
            if hasattr(self, 'connection') and self.connection is not None and not self.connection.closed:
                logging.info("Connection already established.")
                return self.connection  # Don't create a new connection if one is already open

            self.connection = psycopg2.connect(**self.db_config)
            self.connection.set_client_encoding('UTF8')
            self.connection.autocommit = True

            self.cursor = self.connection.cursor()
            self.cursor.execute("SELECT version();")
            record = self.cursor.fetchone()

            logging.info(f"Connected to - {record}")
            return self.connection

        except Exception as error:
            logging.error(f"Failed to connect to the database: {error}")
            raise ConnectionError(f"Failed to connect to the database: {error}")

    def close_connection(self):
        """Close the cursor and the database connection."""
        if self.cursor:
            self.cursor.close()
            self.cursor = None
        if self.connection:
            self.connection.close()
            self.connection = None

    def ensure_connection(self):
        """Ensure an active database connection before any operation."""
        if not hasattr(self, 'connection') or self.connection is None or self.connection.closed:
            logging.info("Database connection not established. Attempting to reconnect.")
            self.connect()


    def create_table(self):
        try:
            self.cursor = self.connection.cursor()
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    fqdn TEXT PRIMARY KEY,
                    certificate TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    valid_until DATE NOT NULL
                )
            """)
            self.connection.commit()
            self.cursor.close()
        except Exception as error:
            logging.info(f"Error creating table: {error}")
        
    def exists_row(self, fqdn):
        self.ensure_connection()
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM certificates WHERE fqdn = %s", (fqdn,))
                return cursor.fetchone() is not None
        except Exception as error:
            logging.error(f"Error checking if row exists: {error}")
            return False


    def insert_row(self, fqdn, certificate, public_key, valid_until):
        try:
            self.ensure_connection()
            self.cursor = self.connection.cursor()
            self.cursor.execute(
                "INSERT INTO certificates (fqdn, certificate, public_key, valid_until) VALUES (%s, %s, %s, %s)",
                (fqdn, certificate, public_key, valid_until))
            self.connection.commit()
            self.cursor.close()
        except Exception as error:
            logging.info(f"Error inserting record: {error}")

    def update_row(self, fqdn, certificate, public_key, valid_until):
        try:
            self.cursor = self.connection.cursor()
            self.cursor.execute("UPDATE certificates SET certificate = %s, public_key = %s, valid_until = %s WHERE fqdn = %s",
                            (certificate, public_key, valid_until, fqdn))
            self.connection.commit()
            self.cursor.close()
        except Exception as error:
            logging.info(f"Error updating row: {error}")

    def delete_row(self, fqdn):
        try:
            self.cursor = self.connection.cursor()
            self.cursor.execute("DELETE FROM certificates WHERE fqdn = %s", (fqdn,))
            self.connection.commit()
            self.cursor.close()
        except Exception as error:
            logging.info(f"Error deleting row: {error}")

    def list_tables(self):
        self.cursor = self.connection.cursor()
        self.cursor.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
        """)
        tables = self.cursor.fetchall()
        self.connection.commit()
        self.cursor.close()

        for table in tables:
            logging.info(table[0])

        return tables

    def show_all_rows(self):
        self.cursor = self.connection.cursor()
        self.cursor.execute("SELECT * FROM certificates")
        rows = self.cursor.fetchall()
        self.connection.commit()
        self.cursor.close()
        return rows

    def get_certificate(self, fqdn):
        try:
            self.cursor = self.connection.cursor()
            if self.connection.closed:
                self.ensure_connection()
            self.cursor.execute("SELECT * FROM certificates WHERE fqdn = %s", (fqdn,))
            result = self.cursor.fetchone()

            if result is None:
                logging.info(f"No certificate found for FQDN: {fqdn}")
                return None
            else:
                return {
                    "fqdn": result[0],
                    "certificate": result[1],
                    "public_key": result[2],
                    "valid_until": result[3]
                }

        except psycopg2.Error as e:
            logging.info(f"Database error: {e}")
            return None

        finally:
            self.connection.commit()
            self.cursor.close()
