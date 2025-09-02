using Microsoft.Win32;
using MidPointWindowsConnectorService.Utility;
using MidPointWindowsConnectorService.Utils;
using NetMQ;
using NetMQ.Sockets;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Diagnostics;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using static MidPointWindowsConnectorService.Utils.Utils;

namespace MidPointWindowsConnectorService.Controller
{
    public class Setup
    {
        public static string MyMachineName = GetMachineFQDN();
        public static InstallationParameters installationParameters = new InstallationParameters();

        public void Start()
        {
            Console.WriteLine("Starting setup...\n");

            if (GetCertFromStore(StoreName.My, "CA_IDMEXT") == null)
            {
                RequestCertificate("CA_IDMEXT");
            }
            if (GetCertFromStore(StoreName.My, "MIDPOINT_IDMEXT") == null)
            {
                RequestCertificate("MIDPOINT_IDMEXT");
            }
            if (GetCertFromStore(StoreName.My, MyMachineName) == null)
            {
                var (publicKey, privateKey) = GenerateRsaKeyPair();
                CreateMyCertificate(publicKey, privateKey);
            }
            RequestResourceIdAndSecret();
            validateResourceIdAndSecret();
        }

        public void RequestResourceIdAndSecret()
        {
            using (var requester = new RequestSocket())
            {
                try
                {
                    string requestUrl = $"{installationParameters.CA_PROTOCOL}{installationParameters.CA_HOST}:{installationParameters.CA_PORT}";
                    requester.Connect(requestUrl);

                    string hostname = Dns.GetHostName();
                    IPHostEntry hostEntry = Dns.GetHostEntry(hostname);

                    var requestData = new Dictionary<string, string>
                    {
                        { "action", "REQUEST_SECRET_PASSWORD" },
                        { "hostname", hostEntry.HostName }
                    };

                    string jsonRequest = JsonConvert.SerializeObject(requestData);
                    requester.SendFrame(jsonRequest);
                    var jsonResponse = requester.ReceiveFrameString();

                    var responseObject = JsonConvert.DeserializeObject<JObject>(jsonResponse);
                    if (responseObject?["status"]?.ToString() == "success")
                    {
                        string? resourceId = responseObject["resource_id"]?.ToString();
                        string? resourceSecret = responseObject["resource_secret"]?.ToString();

                        if (resourceId != null && resourceSecret != null)
                        {
                            SaveInRegistry("RESOURCE_ID", resourceId);
                            SaveInRegistry("RESOURCE_SECRET", resourceSecret);
                        }
                        else
                        {
                            LogToEventViewer("Incomplete response from server.", EventLogEntryType.Error);
                        }
                    }
                    else
                    {
                        LogToEventViewer("Error retrieving resource credentials: " + responseObject?["message"]?.ToString(), EventLogEntryType.Error);
                    }
                }
                catch (Exception ex)
                {
                    LogToEventViewer("Failed to retrieve RESOURCE_ID and RESOURCE_SECRET: " + ex.Message, EventLogEntryType.Error);
                }
            }
        }

        // If RESOURCE_SECRET encrypted, decrypt it
        // If not encrypted, encrypt it and save back
        private void validateResourceIdAndSecret()
        {
            X509Certificate2? machineCert = GetCertFromStore(StoreName.My, MyMachineName);

            if (machineCert == null)
            {
                LogToEventViewer("Machine certificate not found. Cannot validate RESOURCE_ID or RESOURCE_SECRET.", EventLogEntryType.Error);
                return;
            }

            string? storedID = GetFromRegistry("RESOURCE_ID");
            string? storedPassword = GetFromRegistry("RESOURCE_SECRET");

            if (string.IsNullOrEmpty(storedID) || string.IsNullOrEmpty(storedPassword))
            {
                LogToEventViewer("RESOURCE_ID or RESOURCE_SECRET are null or empty", EventLogEntryType.Error);
                throw new Exception("RESOURCE_ID or RESOURCE_SECRET are null or empty.");
            }
            else 
            {
                ensureRegistryKeysAreEncrypted("RESOURCE_ID", storedID, machineCert);
                ensureRegistryKeysAreEncrypted("RESOURCE_SECRET", storedPassword, machineCert);
            }
        }
        private void ensureRegistryKeysAreEncrypted(string key, string registryValue, X509Certificate2 machineCert)
        {
            JObject jsonObject;

            try
            {
                var encryptedBytes = Convert.FromBase64String(registryValue);
                var decryptedBytes = Cryptography.EncryptWithRSA(encryptedBytes, machineCert, false);
                var decryptedText = Encoding.UTF8.GetString(decryptedBytes);

                jsonObject = JObject.Parse(decryptedText);
                if (jsonObject.ContainsKey(key))
                {
                    LogToEventViewer($"{key} is already encrypted.", EventLogEntryType.Information);
                    return;
                }
            }
            catch (Exception ex)
            {
                LogToEventViewer($"Failed to get value of {key}. Not encrypted yet: " + ex.Message, EventLogEntryType.Information);
            
                try
                {
                    string jsonData = CreateJson(key, registryValue);
                    byte[] encryptedPassword = Cryptography.EncryptWithRSA(Encoding.UTF8.GetBytes(jsonData), machineCert, true);
                    string encryptedString = Convert.ToBase64String(encryptedPassword);
                    LogToEventViewer($"Saving encrypted {key}", EventLogEntryType.Information);
                    SaveInRegistry(key, encryptedString);
                }
                catch (Exception e)
                {
                    LogToEventViewer($"Failed to set value for {key}: " + e.Message, EventLogEntryType.Error);
                }
            }
        }

        private static string CreateJson(string key, string value)
        {
            JObject jsonObject = new JObject
            {
                {key,value}
            };
            return jsonObject.ToString();
        }

        public static void SaveInRegistry(string valueName, string encryptedPassword)
        {
            string keyPath = @"Software\eBZ Tecnologia\MidPointWindowsConnectorService";
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(keyPath))
            {
                key.SetValue(valueName, encryptedPassword);
                key.Close();
            }
        }
        public static string? GetFromRegistry(string valueName)
        {
            string keyPath = @"Software\eBZ Tecnologia\MidPointWindowsConnectorService";

            using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath))
            {
                if (key == null)
                {
                    Setup.LogToEventViewer($"Registry key not found: {keyPath}", EventLogEntryType.Warning);
                    return null;
                }

                object? value = key.GetValue(valueName);

                if (value == null)
                {
                    Setup.LogToEventViewer($"Registry value '{valueName}' not found in '{keyPath}'", EventLogEntryType.Warning);
                    return null;
                }

                return value as string ?? value.ToString();
            }
        }

        public static (RsaKeyParameters? Public, RsaPrivateCrtKeyParameters? Private) GetMyKeys()
        {
            X509Certificate2? certificate = GetCertFromStore(StoreName.My, MyMachineName);

            if (certificate == null)
            {
                Setup.LogToEventViewer($"Certificate not found for machine: {MyMachineName}", EventLogEntryType.Warning);
                return (null, null);
            }
            RSA? pubkey = certificate.GetRSAPublicKey();
            RSA? prvkey = certificate.GetRSAPrivateKey();

            if (pubkey == null || prvkey == null)
            {
                Setup.LogToEventViewer("Public or Private key not found in certificate.", EventLogEntryType.Warning);
                return (null, null);
            }

            try
            {
                RsaKeyParameters? publicKey = ReadKeyFromPem<RsaKeyParameters>(pubkey.ExportRSAPublicKeyPem());

                AsymmetricCipherKeyPair? privateKey = ReadKeyFromPem<AsymmetricCipherKeyPair>(prvkey.ExportRSAPrivateKeyPem());

                if (publicKey == null || privateKey == null || privateKey.Private == null)
                {
                    Setup.LogToEventViewer("Failed to extract valid RSA keys from certificate.", EventLogEntryType.Error);
                    return (null, null);
                }

                return (publicKey, (RsaPrivateCrtKeyParameters)privateKey.Private);
            }
            catch (Exception ex)
            {
                Setup.LogToEventViewer($"Error extracting RSA keys: {ex.Message}", EventLogEntryType.Error);
                return (null, null);
            }
        }

        private static T ReadKeyFromPem<T>(string pemKey) where T : class
        {
            if (string.IsNullOrWhiteSpace(pemKey))
            {
                throw new ArgumentException("PEM key cannot be null or empty.", nameof(pemKey));
            }
            using (var reader = new StringReader(pemKey))
            {
                var pemReader = new PemReader(reader);
                object parsedObject = pemReader.ReadObject();
                if (parsedObject == null)
                {
                    throw new FormatException("Failed to parse PEM key. Ensure the format is correct.");
                }
                if (parsedObject is not T keyObject)
                {
                    throw new InvalidCastException($"Parsed PEM key is not of expected type {typeof(T)}.");
                }
                return keyObject;
            }
        }

        public static bool IsCertificateAboutToExpire(X509Certificate2 certificate)
        {
            int days = 10;
            DateTime now = DateTime.UtcNow;
            TimeSpan timeUntilExpiry = certificate.NotAfter - now;
            return timeUntilExpiry.TotalDays <= days;
        }

        public static X509Certificate2? GetCertFromStore(StoreName storeName, string subjectName)
        {
            using (X509Store store = new X509Store(storeName, StoreLocation.LocalMachine))
            {
                try
                {
                    store.Open(OpenFlags.ReadOnly);

                    if (store.Certificates == null || store.Certificates.Count == 0)
                    {
                        return null;
                    }

                    foreach (X509Certificate2 cert in store.Certificates)
                    {
                        if (!string.IsNullOrEmpty(subjectName) && cert.Subject.Contains(subjectName, StringComparison.OrdinalIgnoreCase))
                        {
                            store.Close();
                            return cert;
                        }
                    }
                    return null;
                }
                catch (Exception ex)
                {
                    Setup.LogToEventViewer($"Error retrieving certificate: {ex.Message}", EventLogEntryType.Error);
                    return null;
                }
            }
        }


        public void RequestCertificate(string certificate_name)
        {
            var request_string = "REQUEST_" + certificate_name;
            using (var requester = new RequestSocket())
            {
                try
                {
                    string requestUrl = $"{installationParameters.CA_PROTOCOL}{installationParameters.CA_HOST}:{installationParameters.CA_PORT}";
                    requester.Connect(requestUrl);

                    var requestData = new Dictionary<string, string>
                    {
                        { "action", request_string }
                    };
                    string jsonRequest = JsonConvert.SerializeObject(requestData);

                    requester.SendFrame(jsonRequest);
                    var jsonResponse = requester.ReceiveFrameString();

                    var response = JsonConvert.DeserializeObject<Response>(jsonResponse);
                    if (response?.Status == "error")
                    {
                        var errorResponse = JsonConvert.DeserializeObject<ErrorResponse>(jsonResponse);
                    }
                    else if (response?.Status == "success")
                    {
                        var successResponse = JsonConvert.DeserializeObject<SuccessResponse>(jsonResponse);
                        if (successResponse?.Data != null)
                        {
                            StoreCertificate(ConvertPemToX509(successResponse.Data), StoreName.My, StoreLocation.LocalMachine);
                        }
                    }
                }
                catch (NetMQException ex)
                {
                    LogToEventViewer("Failed to connect to the server: " + ex.Message, EventLogEntryType.Error);
                }
                catch (Exception ex)
                {
                    LogToEventViewer("An unexpected error occurred: " + ex.Message, EventLogEntryType.Error);
                }
            }
        }

        public static void LogToEventViewer(string message, EventLogEntryType type)
        {
            string source = "MidpointWindowsConnectorService";
            string logName = "Application";

            if (!EventLog.SourceExists(source))
            {
                EventLog.CreateEventSource(source, logName);
            }

            using (EventLog eventLog = new EventLog(logName))
            {
                eventLog.Source = source;
                eventLog.WriteEntry(message, type);
            }
        }
        public static void StoreCertificate(X509Certificate2 certificate, StoreName storeName, StoreLocation storeLocation)
        {
            string commonName = GetCertCommonName(certificate);

            using (var store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadWrite);
                X509Certificate2? existingCert = GetCertFromStore(storeName, commonName);

                if (existingCert != null)
                {
                    store.Remove(existingCert);
                }
                store.Add(certificate);
                store.Close();
            }
        }

        public static string ConvertX509ToPem(X509Certificate2 certificate)
        {
            // Convert the .NET X509Certificate2 to BouncyCastle X509Certificate
            var bcCert = DotNetUtilities.FromX509Certificate(certificate);

            using (var stringWriter = new StringWriter())
            {
                var pemWriter = new PemWriter(stringWriter);
                pemWriter.WriteObject(bcCert);
                pemWriter.Writer.Flush();
                return stringWriter.ToString();
            }
        }

        public static X509Certificate2 ConvertPemToX509(string pemCertificate)
        {
            // Remove the PEM headers
            // Convert the Base64 string to a byte array
            // Create an X509Certificate2 object from the byte array
            string pem = pemCertificate.Replace("-----BEGIN CERTIFICATE-----", "")
                                       .Replace("-----END CERTIFICATE-----", "")
                                       .Replace("\r", "")
                                       .Replace("\n", "");
            byte[] certificateBytes = Convert.FromBase64String(pem);
            return new X509Certificate2(certificateBytes);
        }

        static (RsaKeyParameters Public, RsaPrivateCrtKeyParameters Private) GenerateRsaKeyPair(int keySize = 2048)
        {
            // Initialize the key generation parameters, create the key pair generator and initialize it
            // Generate the key pair
            var keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), keySize);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            var keyPair = keyPairGenerator.GenerateKeyPair();
            return ((RsaKeyParameters)keyPair.Public, (RsaPrivateCrtKeyParameters)keyPair.Private);
        }

        public static void CreateMyCertificate(RsaKeyParameters publicKey, RsaPrivateCrtKeyParameters privateKey)
        {
            // Generate CSR request
            // Send CSR request to get signed certificate
            // Put private key
            // Get the key container name
            // Set permissions on the private key file
            // Store signed certificate in Store
            
            var csr = GenerateCSR(publicKey, privateKey);
            X509Certificate2 signedCert = SendCSRSigningRequest(csr);
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            var RSAPrivateKey = DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo));
            X509Certificate2 certificateWithPrivateKey = signedCert.CopyWithPrivateKey(RSAPrivateKey);
            var keyContainerName = GetKeyContainerName(certificateWithPrivateKey);
            if (!string.IsNullOrEmpty(keyContainerName))
            {
                Setup.LogToEventViewer(keyContainerName, EventLogEntryType.Information);
                SetPrivateKeyPermissions(keyContainerName);
            }
            StoreCertificate(certificateWithPrivateKey, StoreName.My, StoreLocation.LocalMachine);
        }

        public static string GenerateCSR(RsaKeyParameters publicKey, RsaPrivateCrtKeyParameters privateKey)
        {
            // Create the subject public key info
            // Define the CSR attributes
            // Create the CSR
            // Convert BouncyCastle CSR to PEM format
            var subject = new X509Name(
                $"C={installationParameters.COUNTRY}, " +
                $"ST={installationParameters.STATE}, " +
                $"L={installationParameters.LOCATION}, " +
                $"O={installationParameters.ORGANIZATION}, " +
                $"OU={installationParameters.ORGANIZATIONAL_UNIT}, " +
                $"CN={MyMachineName}");

            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            var attributes = new DerSet();

            var csr = new Pkcs10CertificationRequest(
                "SHA256WITHRSA",
                subject,
                publicKey,
                attributes,
                privateKey
            );

            StringBuilder csrPem = new StringBuilder();
            var csrPemWriter = new PemWriter(new StringWriter(csrPem));
            csrPemWriter.WriteObject(csr);
            csrPemWriter.Writer.Flush();
            return csrPem.ToString();
        }

        public static X509Certificate2 SendCSRSigningRequest(string csr)
        {
            // Send the JSON request
            // Receive the signed certificate
            // Parse the common part of the response
            using (var requester = new RequestSocket())
            {
                string requestUrl = $"{installationParameters.CA_PROTOCOL}{installationParameters.CA_HOST}:{installationParameters.CA_PORT}";
                requester.Connect(requestUrl);
                Console.WriteLine("Sending CSR to CA...");
                var requestData = new Dictionary<string, string>
                {
                    { "action", "REQUEST_SIGNED_CERTIFICATE" },
                    { "csr", csr }
                };
                string jsonRequest = JsonConvert.SerializeObject(requestData);
                requester.SendFrame(jsonRequest);
                var jsonResponse = requester.ReceiveFrameString();
                var response = JsonConvert.DeserializeObject<Response>(jsonResponse);

                if (response?.Status == "error")
                {
                    var errorResponse = JsonConvert.DeserializeObject<ErrorResponse>(jsonResponse);
                    throw new Exception(errorResponse?.Message);
                }
                else if (response?.Status == "success")
                {
                    var successResponse = JsonConvert.DeserializeObject<SuccessResponse>(jsonResponse);
                    if (successResponse?.Data != null)
                    {
                        return ConvertPemToX509(successResponse.Data);
                    }
                    else
                    {
                        throw new Exception("null response");
                    }
                }
                else 
                { 
                    throw new Exception("Unknown response status");
                }
            }
        }

        private static string? GetKeyContainerName(X509Certificate2 certificate)
        {
            using (var rsa = certificate.GetRSAPrivateKey() as RSACryptoServiceProvider)
            {
                if (rsa != null)
                {
                    return rsa.CspKeyContainerInfo.UniqueKeyContainerName;
                }
            }
            return null;
        }

        private static void SetPrivateKeyPermissions(string keyContainerName)
        {
            var machineKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Crypto\RSA\MachineKeys");
            var keyFilePath = Path.Combine(machineKeyPath, keyContainerName);

            var fileInfo = new FileInfo(keyFilePath);
            var fileSecurity = fileInfo.GetAccessControl();

            var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            var accessRule = new FileSystemAccessRule(everyone, FileSystemRights.FullControl, AccessControlType.Allow);

            fileSecurity.AddAccessRule(accessRule);
            fileInfo.SetAccessControl(fileSecurity);
        }

        public static string GetCertCommonName(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                Setup.LogToEventViewer("Certificate is null in GetCertCommonName.", EventLogEntryType.Warning);
                return "UnknownCN";
            }
            string subject = certificate.Subject;
            if (string.IsNullOrWhiteSpace(subject))
            {
                Setup.LogToEventViewer("Certificate subject is empty or missing.", EventLogEntryType.Warning);
                return "UnknownCN";
            }
            try
            {
                string[] subjectParts = subject.Split(',');

                foreach (string part in subjectParts)
                {
                    string trimmedPart = part.Trim();
                    if (trimmedPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    {
                        return trimmedPart.Substring(3).Trim();
                    }
                }
                Setup.LogToEventViewer("CN (Common Name) not found in certificate subject.", EventLogEntryType.Warning);
                return "UnknownCN";
            }
            catch (Exception ex)
            {
                Setup.LogToEventViewer($"Error extracting CN: {ex.Message}", EventLogEntryType.Error);
                return "UnknownCN";
            }
        }


        public class Response
        {
            public required string Status { get; set; }
        }
        public class ErrorResponse : Response
        {
            public required string Message { get; set; }
        }
        public class SuccessResponse : Response
        {
            public required string Data { get; set; }
        }

    }
}
