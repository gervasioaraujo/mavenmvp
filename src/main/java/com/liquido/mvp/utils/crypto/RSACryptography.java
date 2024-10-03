package com.liquido.mvp.utils.crypto;

import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.bouncycastle.util.io.pem.PemReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import java.security.MessageDigest;

public class RSACryptography {

    // Carrega uma chave pública de um arquivo .pem
    public static PublicKey loadPublicKeyFromPEM(String filePath) throws Exception {
        PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(filePath), StandardCharsets.UTF_8));
        byte[] pemBytes = pemReader.readPemObject().getContent();
        pemReader.close();

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    // Alternativa: Carrega chave pública de um certificado X.509
    public static PublicKey loadPublicKeyFromCertificate(String certificatePath) throws Exception {
        FileInputStream fis = new FileInputStream(certificatePath);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(fis);
        return certificate.getPublicKey();
    }

    // Criptografa a chave AES com a chave pública RSA
    // public static byte[] encryptAESKeyWithRSA(SecretKey aesKey, PublicKey publicKey) throws Exception {
    public static String encryptAESKeyWithRSA(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // RSA-1_5
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Criptografa a chave AES
        byte[] cipherText = cipher.doFinal(aesKey.getEncoded());
        // return cipher.doFinal(aesKey.getEncoded());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String generateSKIFromPublicKeyWithSHA1(PublicKey publicKey) throws NoSuchAlgorithmException {
        // Gerar o SKI usando SHA-1
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        // Extrair os bytes da chave pública
        byte[] encodedPublicKey = publicKey.getEncoded();

        byte[] skiBytes = sha1.digest(encodedPublicKey);

        // Converter o SKI para Base64 para exibir
        return Base64.getEncoder().encodeToString(skiBytes);
    }

    // Método para gerar o Subject Key Identifier a partir da chave pública
    public static String generateSubjectKeyIdentifier(PublicKey publicKey) throws NoSuchAlgorithmException {
        // Extrair os bytes da chave pública
        byte[] encodedPublicKey = publicKey.getEncoded();

        // Gerar o Subject Key Identifier (usando o método SHA-1 como base)
        SubjectKeyIdentifier ski = new SubjectKeyIdentifier(encodedPublicKey);

        // Converter o SKI para Base64 para exibir
        return Base64.getEncoder().encodeToString(ski.getKeyIdentifier());
    }

    /*public static void main(String[] args) {
        try {
            // Gera chave AES-256 efêmera
            SecretKey aesKey = generateAESKey();

            // Carrega chave pública a partir de um arquivo PEM
            String publicKeyPath = "caminho/para/sua/chave_publica.pem";
            PublicKey publicKey = loadPublicKeyFromPEM(publicKeyPath);

            // Alternativa: Carregar chave pública de um certificado
            // String certificatePath = "caminho/para/seu_certificado.crt";
            // PublicKey publicKey = loadPublicKeyFromCertificate(certificatePath);

            // Criptografa a chave AES com a chave pública
            byte[] encryptedAESKey = encryptAESKeyWithRSA(aesKey, publicKey);

            // Codifica a chave criptografada em Base64 para facilitar o uso
            String encryptedAESKeyBase64 = Base64.getEncoder().encodeToString(encryptedAESKey);

            System.out.println("Chave AES criptografada (Base64): " + encryptedAESKeyBase64);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }*/

    /*
    * Explicação

    loadPublicKeyFromPEM: Carrega uma chave pública a partir de um arquivo .pem (que contém a chave pública no formato PEM). Para isso, usamos PemReader da BouncyCastle, mas isso pode ser feito sem BouncyCastle se o PEM estiver em formato base64 puro.
    loadPublicKeyFromCertificate: Alternativamente, você pode carregar uma chave pública diretamente de um certificado X.509.
    encryptAESKeyWithRSA: Usa o algoritmo RSA/ECB/PKCS1Padding (correspondente a RSA-1_5) para criptografar a chave AES gerada.
    Base64: A chave AES criptografada é convertida em Base64 para facilitar o armazenamento ou a transmissão.
    Observações
    O modo de criptografia RSA utilizado é RSA/ECB/PKCS1Padding, que equivale ao RSA-1_5 no contexto do WSS4J.
    Certifique-se de que a chave pública esteja correta e no formato adequado, seja no PEM ou no certificado X.509.
    Para um arquivo .pem, ele deve conter a chave pública no formato padrão, como:
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkq...
    -----END PUBLIC KEY-----
    Se você estiver usando um certificado em vez de um arquivo .pem direto, o método alternativo loadPublicKeyFromCertificate pode ser usado.
    * */
}

