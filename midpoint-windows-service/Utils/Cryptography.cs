using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.IO.Compression;
using static System.Convert;
using Newtonsoft.Json;
using System.Diagnostics;
using Org.BouncyCastle.Crypto.Encodings;
using MidPointWindowsConnectorService.Controller;

namespace MidPointWindowsConnectorService.Utility
{
    public static class Cryptography
    {

        public class ResponsePackage
        {
            public string? EncryptedAESKey { get; set; }
            public string? IV { get; set; }
            public string? EncryptedData { get; set; }
            public string? Tag { get; set; }
            public string? ResourceID { get; set; }
            public string? ResourceSec {  get; set; }
        }

        private const int AES_KEY_SIZE = 32; // AES-256 key size
        private const int IV_SIZE = 12; // 12 bytes IV for AES-GCM
        private const int TAG_SIZE = 16; // 16 bytes authentication tag
    

        // Generate a secure AES-256 key
        private static byte[] GenerateAESKey()
        {
            byte[] key = new byte[AES_KEY_SIZE];
            RandomNumberGenerator.Fill(key);
            return key;
        }

        // Generate a secure random IV
        private static byte[] GenerateIV()
        {
            byte[] iv = new byte[IV_SIZE];
            RandomNumberGenerator.Fill(iv);
            return iv;
        }


        // This function encrypts a message by performing the following steps:
        // Generate an AES Key and IV
        // Compress data
        // Encrypt the data using the AES key and the IV
        // Encrypt the AES key using the RSA midpoint public key
        // Return a string with encrypted AES key, IV and encrypted data 
        public static string encryptMessage(byte[] message, X509Certificate2 machineCert)
        {
            /*
            var aesKey = new byte[32];
            var iv = new byte[16];
            RandomNumberGenerator.Fill(aesKey);
            RandomNumberGenerator.Fill(iv);
             */

            byte[] aesKey = GenerateAESKey();
            byte[] iv = GenerateIV();

            byte[] compressedData = Compress(message);
            byte[] encryptedData = EncryptWithAES(aesKey, iv, compressedData, out byte[] tag);
            byte[] encryptedAESKey = EncryptWithRSA(aesKey, machineCert, true);

            ResponsePackage response = new ResponsePackage
            {
                EncryptedAESKey = ToBase64String(encryptedAESKey),
                IV = ToBase64String(iv),
                EncryptedData = Convert.ToBase64String(ConcatArrays(encryptedData, tag))
            };
            return JsonConvert.SerializeObject(response);
        }

        // This function decrypts an encrypted message by performing the following steps:
        // Split the encrypted message into its three parts (Base64 encoded)
        // Decode the Base64-encoded parts into byte arrays (AESKey, IV, Data)
        // Decrypt the AES key using the RSA private key
        // Decrypt the data using the decrypted AES key and the IV.
        // Decompress the decrypted data to get the original message.
        // Return the decompressed byte array converted into a UTF-8 string
        public static string decryptMessage(byte[] encryptedMessage, X509Certificate2 machineCert)
        {
            if (encryptedMessage == null || encryptedMessage.Length == 0)
            {
                Setup.LogToEventViewer("Encrypted message is null or empty.", EventLogEntryType.Warning);
                return "DecryptionError: Empty message.";
            }
            if (machineCert == null)
            {
                Setup.LogToEventViewer("Machine certificate is null. Cannot decrypt message.", EventLogEntryType.Error);
                return "DecryptionError: Missing certificate.";
            }

            try
            {
                string jsonString = Encoding.UTF8.GetString(encryptedMessage);
                ResponsePackage? message = JsonConvert.DeserializeObject<ResponsePackage>(jsonString);

                if (message == null)
                {
                    Setup.LogToEventViewer("Failed to parse JSON message.", EventLogEntryType.Warning);
                    return "DecryptionError: Invalid JSON format.";
                }

                if (string.IsNullOrEmpty(message.EncryptedAESKey) || string.IsNullOrEmpty(message.IV) ||
                    string.IsNullOrEmpty(message.EncryptedData) || string.IsNullOrEmpty(message.Tag))
                {
                    Setup.LogToEventViewer("Missing encryption components in JSON message.", EventLogEntryType.Warning);
                    return "DecryptionError: Missing encryption components.";
                }

                byte[] encryptedAESKey;
                byte[] iv;
                byte[] encryptedData;
                byte[] tag;

                try
                {
                    encryptedAESKey = Convert.FromBase64String(message.EncryptedAESKey);
                    iv = Convert.FromBase64String(message.IV);
                    encryptedData = Convert.FromBase64String(message.EncryptedData);
                    tag = Convert.FromBase64String(message.Tag);
                }
                catch (FormatException)
                {
                    Setup.LogToEventViewer("Invalid Base64 encoding in JSON message.", EventLogEntryType.Warning);
                    return "DecryptionError: Invalid Base64 format.";
                }

                if (iv.Length != IV_SIZE)
                {
                    Setup.LogToEventViewer($"Invalid IV size: {iv.Length}. Expected {IV_SIZE} bytes.", EventLogEntryType.Warning);
                    return "DecryptionError: Invalid IV size.";
                }

                if (tag.Length != TAG_SIZE)
                {
                    Setup.LogToEventViewer($"Invalid Tag size: {tag.Length}. Expected {TAG_SIZE} bytes.", EventLogEntryType.Warning);
                    return "DecryptionError: Invalid Tag size.";
                }

                byte[] aesKey;
                try
                {
                    aesKey = EncryptWithRSA(encryptedAESKey, machineCert, false);
                }
                catch (CryptographicException)
                {
                    Setup.LogToEventViewer("Failed to decrypt AES key with RSA.", EventLogEntryType.Error);
                    return "DecryptionError: RSA decryption failed.";
                }

                byte[] decryptedData;
                try
                {
                    decryptedData = DecryptWithAES(aesKey, iv, encryptedData, tag);
                }
                catch (CryptographicException)
                {
                    Setup.LogToEventViewer("AES decryption failed.", EventLogEntryType.Error);
                    return "DecryptionError: AES decryption failed.";
                }

                byte[] decompressed;
                try
                {
                    decompressed = Decompress(decryptedData);
                }
                catch (InvalidDataException)
                {
                    Setup.LogToEventViewer("Decompression failed.", EventLogEntryType.Error);
                    return "DecryptionError: Decompression failed.";
                }

                return Encoding.UTF8.GetString(decompressed);
            }
            catch (Exception ex)
            {
                Setup.LogToEventViewer($"Unexpected error during decryption: {ex.Message}", EventLogEntryType.Error);
                return "DecryptionError: An unexpected error occurred.";
            }
        }


        // Get RSA public/private key from X509 certificate based on encryption/decryption flag
        // Get Bouncy Castle parameters from RSA key based on encryption/decryption flag
        // Initialize the RSA engine for encryption or decryption and process the data
        public static byte[] EncryptWithRSA(byte[] data, X509Certificate2 machineCert, Boolean isEncryption)
        {
            AsymmetricKeyParameter rsaKeyParams;

            if (isEncryption)
            {
                var rsaKey = machineCert.GetRSAPublicKey();
                rsaKeyParams = DotNetUtilities.GetRsaPublicKey(rsaKey);
            }
            else
            {
                var rsaKey = machineCert.GetRSAPrivateKey();
                if (rsaKey == null)
                    throw new Exception("Private key not found in certificate.");

                byte[] pkcs8PrivateKey = rsaKey.ExportPkcs8PrivateKey();
                rsaKeyParams = PrivateKeyFactory.CreateKey(pkcs8PrivateKey);
            }

            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine());
            cipher.Init(isEncryption, rsaKeyParams);

            return cipher.ProcessBlock(data, 0, data.Length);
        }

        // Returns a compressed byte array
        private static byte[] Compress(byte[] data)
        {
            using (var outputStream = new MemoryStream())
            {
                using (var brotliStream = new BrotliStream(outputStream, CompressionMode.Compress))
                {
                    brotliStream.Write(data, 0, data.Length);
                }
                return outputStream.ToArray();
            }
        }
        // Returns a decompressed byte array
        private static byte[] Decompress(byte[] data)
        {
            using (var inputStream = new MemoryStream(data))
            {
                using (var brotliStream = new BrotliStream(inputStream, CompressionMode.Decompress))
                {
                    using (var outputStream = new MemoryStream())
                    {
                        brotliStream.CopyTo(outputStream);
                        return outputStream.ToArray();
                    }
                }
            }
        }
        private static byte[] EncryptWithAES(byte[] key, byte[] iv, byte[] data, out byte[] tag)
        {
            byte[] encryptedData = new byte[data.Length];
            tag = new byte[TAG_SIZE];

            using (AesGcm aes = new AesGcm(key, tag.Length))
            {
                aes.Encrypt(iv, data, encryptedData, tag);
            }

            return encryptedData;
        }
       
        // Decrypt data with AES-GCM
        private static byte[] DecryptWithAES(byte[] key, byte[] iv, byte[] encryptedData, byte[] tag)
        {
            byte[] decryptedData = new byte[encryptedData.Length];

            using (AesGcm aes = new AesGcm(key, tag.Length))
            {
                aes.Decrypt(iv, encryptedData, tag, decryptedData);
            }

            return decryptedData;
        }

        // Concatenates two byte arrays
        private static byte[] ConcatArrays(byte[] array1, byte[] array2)
        {
            byte[] result = new byte[array1.Length + array2.Length];
            Buffer.BlockCopy(array1, 0, result, 0, array1.Length);
            Buffer.BlockCopy(array2, 0, result, array1.Length, array2.Length);
            return result;
        }
    }
}
