package com.liquido.mvp.utils.crypto;

import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
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

    /*// Alternativa: Carrega chave pública de um certificado X.509
    public static PublicKey loadPublicKeyFromCertificate(String certificatePath) throws Exception {
        FileInputStream fis = new FileInputStream(certificatePath);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(fis);
        return certificate.getPublicKey();
    }*/

    // Criptografa a chave AES com a chave pública RSA
    public static String encryptAESKeyWithRSA_V1(String aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // RSA-1_5
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Criptografa a chave AES
        byte[] cipherText = cipher.doFinal(aesKey.getBytes());
        // return cipher.doFinal(aesKey.getEncoded());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // Criptografa a chave AES com a chave pública RSA
    // public static byte[] encryptAESKeyWithRSA(SecretKey aesKey, PublicKey publicKey) throws Exception {
    public static String encryptAESKeyWithRSA_V2(SecretKey aesKey, PublicKey publicKey) throws Exception {
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

    // ######################################
    // workaround
    public static PublicKey getFakePublicKey() {

        // A string fornecida representando o módulo da chave pública
        String modulusString = "807744312583133394477498744621226914171017744380785411315030771326780550311859827092954574160543236215261492900615891131414221079755274516422040943595487528742741715823101373085834897805978923604671408631595238601404323136743512499411306315216766582897809604682016826972027283085764222774213027282343900575356929995975834086387603546027575916753482111791711871051728085516027758365065486421223218568207459071984950800314743226463295819343326219572938419997428657334922801407099967160366737099505161832222285381390335747073313751033377700991232770601394817019687016657982533431552379766823720515131039629072962463415090950410398038780249019218415822182914980288522500415042867241036275861698139565791043479598752252106969874053186658413582314297185527862045632364961191544015415686747675307181037116507326842084062236178504199370426839770755025606707327306421003911887132937046081640926920857340848802762159199255537975350790761562023070250822205437328689212432526886354160111154730120330740666261843591110827079984830261893949080770357254018122920936311350371382029334920467299742601638822631205789664006358633495997473504316041367930934352946538662295482853766783811141291209703397560780752246050163654339084866232225874056015245977";

        // Converter o módulo da chave pública de string para BigInteger
        BigInteger modulus = new BigInteger(modulusString);

        // Definir o expoente público padrão (65537 é o valor comum para RSA)
        BigInteger publicExponent = BigInteger.valueOf(65537);

        // Criar a especificação da chave pública RSA
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
        // RSAPublicKeySpec keySpec = new RSAPublicKeySpec();

        // Obter a instância de KeyFactory para RSA
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // Gerar a chave pública a partir da especificação
        PublicKey publicKey = null;
        try {
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        return publicKey;

        // Exibir a chave pública em formato X.509 (codificada em Base64)
        /*byte[] encodedPublicKey = publicKey.getEncoded();
        String publicKeyString = Base64.getEncoder().encodeToString(encodedPublicKey);

        System.out.println("Chave Pública X.509 em Base64:");
        System.out.println(publicKeyString);*/
    }
}

