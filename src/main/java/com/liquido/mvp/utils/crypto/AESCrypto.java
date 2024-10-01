package com.liquido.mvp.utils.crypto;

/*import org.apache.wss4j.common.crypto.WSSecurityEngineResult;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;*/
import org.apache.xml.security.utils.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
// import java.util.Arrays;

public class AESCrypto {

    /*public static void main(String[] args) throws Exception {
        String plainText = "Texto a ser criptografado";
        // Gera chave efêmera AES-256
        SecretKey secretKey = generateAESKey(256);

        // Gera IV aleatório de 16 bytes (128 bits) para AES-CBC
        byte[] iv = generateIV(16);

        // Criptografa a string
        String encryptedText = encrypt(plainText, secretKey, iv);

        System.out.println("Texto criptografado: " + encryptedText);
    }*/

    // Gera uma chave AES
    private static SecretKey generateAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize, new SecureRandom());
        return keyGen.generateKey();
    }

    // Gera um IV aleatório
    private static byte[] generateIV(int length) {
        byte[] iv = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    // Função para criptografar usando AES-256-CBC
    private static String encrypt(String plainText, SecretKey secretKey, byte[] iv) throws Exception {
        // Inicializa o Cipher com AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        // Criptografa o texto em bytes
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Codifica os bytes criptografados e o IV em Base64 para exibição
        String encryptedTextBase64 = Base64.encode(encryptedBytes);
        String ivBase64 = Base64.encode(iv);

        // Retorna o IV e o texto criptografado, ambos em Base64
        return ivBase64 + ":" + encryptedTextBase64;
    }

    /*
    * Explicação:
    Geração da chave AES efêmera: A chave é gerada dinamicamente para cada execução do código usando KeyGenerator com o algoritmo AES e tamanho de 256 bits.
    Geração do IV: O vetor de inicialização (IV) de 128 bits é gerado aleatoriamente e é necessário para o modo CBC (Cipher Block Chaining).
    Criptografia com AES-256-CBC: O Cipher é inicializado para criptografar com o modo AES/CBC/PKCS5Padding. A chave gerada e o IV são utilizados para criptografar a string.
    Codificação Base64: Tanto o texto criptografado quanto o IV são codificados em Base64 para facilitar o armazenamento ou transmissão.

    Esse código é um exemplo básico para criptografar uma string com AES-256-CBC e uma chave efêmera. Certifique-se de que o algoritmo AES-256 esteja habilitado no seu ambiente JDK, pois ele pode exigir bibliotecas de extensão de política de criptografia de força total (JCE Unlimited Strength Jurisdiction Policy Files).
    * */
}

