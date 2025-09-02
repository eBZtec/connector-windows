package br.tec.ebz.polygon.connector.windowslocalaccount;


import com.aayushatharva.brotli4j.Brotli4jLoader;
import com.aayushatharva.brotli4j.decoder.BrotliInputStream;
import com.aayushatharva.brotli4j.encoder.BrotliOutputStream;
import com.aayushatharva.brotli4j.encoder.Encoder;
import kong.unirest.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;

import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.KeyGenerator;

import static java.util.Base64.getEncoder;

public class Cryptography {

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12;
    private static final int TAG_SIZE = 16;


    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom()); // SecureRandom for added security
        return keyGen.generateKey();
    }

    public static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    public static JSONObject encryptDataWithAESKey(SecretKey secretKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);

        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] encryptedDataWithTag = cipher.doFinal(data);

        byte[] tag = new byte[TAG_SIZE];
        System.arraycopy(encryptedDataWithTag, encryptedDataWithTag.length - TAG_SIZE, tag, 0, TAG_SIZE);

        byte[] encryptedData = new byte[encryptedDataWithTag.length - TAG_SIZE];
        System.arraycopy(encryptedDataWithTag, 0, encryptedData, 0, encryptedData.length);

        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedDataWithTag.length);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedDataWithTag);

        JSONObject json = new JSONObject();
        json.put("EncryptedData", Base64.getEncoder().encodeToString(encryptedData));
        json.put("Tag", Base64.getEncoder().encodeToString(tag));
        json.put("IV", Base64.getEncoder().encodeToString(iv));

        return json;
    }

    public static byte[] decryptDataWithAESKey(SecretKey aesKey, byte[] iv, byte[] encryptedData) throws Exception {

        byte[] random_iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(random_iv);

        random_iv = iv;

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE * 8, random_iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        return cipher.doFinal(encryptedData);
    }

    public static byte[] encryptAESKeyWithRSAKey(PublicKey publicKey, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.WRAP_MODE, publicKey);
        return cipher.wrap(secretKey);
    }

    public static byte[] decryptAESKeyWithRSAKey(PrivateKey privateKey, byte[] encryptedAESKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        return cipher.unwrap(encryptedAESKey, "AES", Cipher.SECRET_KEY).getEncoded();
    }


    public static byte[] compress(byte[] data) throws IOException {
        Brotli4jLoader.ensureAvailability();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Encoder.Parameters params = new Encoder.Parameters().setQuality(4);

        try (BrotliOutputStream brotliOutputStream = new BrotliOutputStream(outputStream, params)) {
            brotliOutputStream.write(data);
        }
        return outputStream.toByteArray();
    }

    public static byte[] decompress(byte[] data) throws Exception {
        Brotli4jLoader.ensureAvailability();
        try (ByteArrayInputStream inStream = new ByteArrayInputStream(data);
             BrotliInputStream brotliInputStream = new BrotliInputStream(inStream);
             ByteArrayOutputStream outStream = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = brotliInputStream.read(buffer)) != -1) {
                outStream.write(buffer, 0, bytesRead);
            }
            return outStream.toByteArray();
        }
    }
}
