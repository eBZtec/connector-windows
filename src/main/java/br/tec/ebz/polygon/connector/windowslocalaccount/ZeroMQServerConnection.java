package br.tec.ebz.polygon.connector.windowslocalaccount;

import com.evolveum.polygon.common.GuardedStringAccessor;
import kong.unirest.json.JSONObject;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;
import java.security.PublicKey;
import java.util.List;

import static java.util.Base64.getEncoder;

public class ZeroMQServerConnection {
    private static final Log LOG = Log.getLog(ZeroMQServerConnection.class);
    private final WindowsLocalAccountConfiguration windowsLocalAccountConfiguration;

    private PublicKey publicCertificateKey;
    private PrivateKey myPrivateKey;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public ZeroMQServerConnection(WindowsLocalAccountConfiguration windowsLocalAccountConfiguration) {
        this.windowsLocalAccountConfiguration = windowsLocalAccountConfiguration;
        getPublicCertificate();
    }
    /*
    This function sends a request to a server and processes the response. Steps performed:
    1. Creates a ZeroMQ context and REQ socket and connects to the server
    2. Sends the processed request to the server
    3. Receives the server's reply as a byte array
    4. Processes the reply and checks for errors
    5. Returns the processed reply as a JSONObject.
    */
    public JSONObject send(String request)  {
        String protocol = "tcp://";

        try (ZContext context = new ZContext()) {
            ZMQ.Socket socket = context.createSocket(SocketType.REQ);

            socket.connect(protocol + this.windowsLocalAccountConfiguration.getHost());
            socket.setReceiveTimeOut(this.windowsLocalAccountConfiguration.getServerReceiveTimeout());

            JSONObject jsonObject = new JSONObject(request);
            String encryptedRequest = processRequest(jsonObject);
            socket.send(encryptedRequest.getBytes());
            LOG.ok("Request send successfully to the server. Waiting for reply...");

            byte[] serverReply = socket.recv(0);
            String reply = new String(serverReply, ZMQ.CHARSET);

            JSONObject decodedReply = processReply(reply);
            socket.close();
            return decodedReply;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private void addResourceIdAndSecret (JSONObject request) {
        GuardedStringAccessor accessor = new GuardedStringAccessor();
        GuardedString password = this.windowsLocalAccountConfiguration.getResourceSecret();
        password.access(accessor);

        request.put("resourceID", this.windowsLocalAccountConfiguration.getResourceID());
        request.put("resourceSecret", accessor.getClearString());
    }
    /*
    This function prepares the request for sending to WindowsLocalService. Steps performed:
    1. Generate an AES Key and IV for symmetric encryption
    2. Compress JSON request before encryption
    3. Encrypts JSON request with AES Key and IV
    4. Encrypts the AES Key with Windows computer public key
    5. Returns a JSON object as a string with encrypted AES key, IV and encrypted request (Base64 encoding)
    */
    private String processRequest(JSONObject request) throws Exception {

        SecretKey aesKey = Cryptography.generateSecretKey();
        addResourceIdAndSecret(request);

        byte[] compressedData = Cryptography.compress(request.toString().getBytes());
        JSONObject encryptedData = Cryptography.encryptDataWithAESKey(aesKey, compressedData);

        byte[] encryptedAESKey = Cryptography.encryptAESKeyWithRSAKey(publicCertificateKey, aesKey);

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("EncryptedAESKey", getEncoder().encodeToString(encryptedAESKey));
        jsonObject.put("EncryptedData", encryptedData.getString("EncryptedData"));
        jsonObject.put("Tag", encryptedData.getString("Tag"));
        jsonObject.put("IV", encryptedData.getString("IV"));

        //System.out.println(jsonObject.toString(4));
        return jsonObject.toString();
    }
    /*
    This function processes the response received from WindowsLocalService. Steps performed:
    1. Parses the JSON string
    2. Decodes the Base64-encoded strings of JSONObject into byte arrays (AESKey, IV, Data)
    3. Retrieves the RSA private key from keystore
    4. Decrypts the AES key using the RSA private key
    5. Decrypts the data using the decrypted AES key and the IV
    6. Decompress the decrypted data to get the original response
    7. Returns the decompressed byte array as a string
    */
    private JSONObject processReply(String reply) throws Exception {

        JSONObject jsonObj = new JSONObject(reply);
        String aes_key = jsonObj.getString("EncryptedAESKey");
        String iv_str = jsonObj.getString("IV");
        String data = jsonObj.getString("EncryptedData");

        byte[] encryptedAESKey = Base64.getDecoder().decode(aes_key);
        byte[] IV = Base64.getDecoder().decode(iv_str);
        byte[] encryptedData = Base64.getDecoder().decode(data);

        extractPrivateKeyFromFile();

        byte[] aesKeyBytes = Cryptography.decryptAESKeyWithRSAKey(myPrivateKey, encryptedAESKey);
        byte[] decryptedData = Cryptography.decryptDataWithAESKey(new SecretKeySpec(aesKeyBytes, "AES"), IV, encryptedData);
        byte[] decompressedData = Cryptography.decompress(decryptedData);

        String jsonOutput = new String(decompressedData, StandardCharsets.UTF_8);
        return new JSONObject(jsonOutput);
    }

    public static boolean isJSONValid(String jsonInString) {
        try {
            new JSONObject(jsonInString);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    public void extractPublicKeyFromPem(String pemCertificate) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        PEMParser pemParser = new PEMParser(new StringReader(pemCertificate));
        X509CertificateHolder certificateHolder = (X509CertificateHolder) pemParser.readObject();
        pemParser.close();

        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
        publicCertificateKey = certificate.getPublicKey();
    }

    public void extractPrivateKeyFromFile() {
        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
                GuardedStringAccessor accessor = new GuardedStringAccessor();
                GuardedString password = this.windowsLocalAccountConfiguration.getKeystorePassword();
                password.access(accessor);

            try (FileInputStream fis = new FileInputStream(this.windowsLocalAccountConfiguration.getKeystoreFile())) {
                keystore.load(fis, accessor.getClearString().toCharArray());
            }

            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keystore.isKeyEntry(alias)) {
                    myPrivateKey = (PrivateKey) keystore.getKey(alias, accessor.getClearString().toCharArray());
                }
            }
        } catch (Exception e) {
            throw new ConfigurationException(e.getMessage());
        }
    }

    private void getPublicCertificate() {
        String hosts = windowsLocalAccountConfiguration.getHostsCA(); // e.g., "host1:port;host2:port;host3:port"
        String[] hostArray = hosts.split(";");
        boolean connected = false;

        try (ZContext context = new ZContext()) {
            ZMQ.Socket requester = context.createSocket(SocketType.REQ);

            for (String host : hostArray) {
                try {
                    requester.connect("tcp://" + host.trim());
                    connected = true;
                    break;
                } catch (Exception e) {
                    LOG.info("Failed to connect to " + host + ": " + e.getMessage());
                }
            }
            if (!connected) {
                throw new ConfigurationException("Could not connect to any CA host.");
            }

            JSONObject jsonRequest = new JSONObject();
            jsonRequest.put("action", "REQUEST_USER_CERTIFICATE");
            jsonRequest.put("data", this.windowsLocalAccountConfiguration.getWindowsHost());

            requester.setReceiveTimeOut(this.windowsLocalAccountConfiguration.getServerReceiveTimeout());
            requester.send(jsonRequest.toString().getBytes(ZMQ.CHARSET), 0);

            byte[] reply = requester.recv(0);
            if (reply != null) {
                String received = new String(reply, ZMQ.CHARSET);

                if (isJSONValid(received)) {
                    JSONObject jsonResponse = new JSONObject(received);

                    if (jsonResponse.getString("status").equals("erro")) {
                        throw new ConfigurationException(jsonResponse.getString("message"));
                    }

                    String certificate = jsonResponse.getString("data");
                    try {
                        extractPublicKeyFromPem(certificate);
                    } catch (Exception e) {
                        throw new ConfigurationException("Could not extract public key from the host, reason: " + e.getMessage());
                    }
                } else {
                    throw new ConfigurationException("Could not extract public from the host, reason: invalid JSON");
                }
            }
            requester.close();
        }
    }
}
