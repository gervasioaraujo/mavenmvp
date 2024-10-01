package com.liquido.mvp.utils.crypto;

/*import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.WSSecEncrypt;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.WSHandlerResult;*/
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESCryptography {

    // Generate a AES 256 bits Secret Key
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Define to AES-256
        return keyGen.generateKey();
    }

    // Generate a random 16 bytes (128 bits) IV (Initialization Vector)
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16]; // IV size for AES-CBC is 16 bytes
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Encrypt a string with AES-256-CBC
    public static String encrypt(String plainText, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] cipherText = cipher.doFinal(plainText.getBytes());

        // Encodes to Base64 for easy storage/transmission
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /*// Método principal de exemplo
    public static void main(String[] args) {
        try {
            // String a ser criptografada
            String plainText = "Texto de exemplo para criptografia";

            // Gera chave AES-256 efêmera e IV
            SecretKey secretKey = generateAESKey();
            IvParameterSpec iv = generateIv();

            // Criptografa o texto
            String cipherText = encrypt(plainText, secretKey, iv);

            System.out.println("Texto original: " + plainText);
            System.out.println("Texto criptografado (Base64): " + cipherText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }*/

    /*
    * Explicação
    KeyGenerator: Usado para gerar uma chave AES de 256 bits.
    IvParameterSpec: Um IV (vetor de inicialização) é necessário para o modo CBC do AES.
    Cipher: A classe Cipher é usada para realizar a criptografia. A criptografia ocorre com o algoritmo AES/CBC/PKCS5Padding.
    Base64: A criptografia gera bytes que não são diretamente legíveis. Para facilitar a transmissão ou armazenamento, o resultado criptografado é codificado em Base64.

    * Esse código cria uma chave AES de 256 bits efêmera e um IV, criptografa a string e retorna o texto criptografado em Base64.

    Se você estiver utilizando o Apache WSS4J principalmente para segurança WS-Security, ele permite gerenciar criptografia de forma mais ampla (como em mensagens SOAP), mas a criptografia básica de strings pode ser feita com Java padrão como mostrado acima.
    * */
}

