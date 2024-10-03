package com.liquido.mvp.utils;

import java.io.StringWriter;
import java.util.Properties;

import org.w3c.dom.Document;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.WSEncryptionPart;
// import org.apache.wss4j.dom.engine.WSSConfig; // *************
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
/*import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;*/
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.w3c.dom.Node;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Wss4jUtils {

    /*
    * see: https://ws.apache.org/wss4j/xref/org/apache/wss4j/dom/processor/EncryptedKeyProcessor.html
    * */
    /*public static String generateEphemeralKey() throws WSSecurityException {

        final var size = KeyUtils.getKeyLength(WSConstants.AES_256);
        System.out.println("########### size: ############");
        System.out.println(size);
        System.out.println("#######################");

        // Gera 32 bytes aleatórios para uma chave AES-256
        SecureRandom random = new SecureRandom();
        // byte[] bytes = new byte[size];
        byte[] bytes = new byte[32]; // 32 bytes = 256 bits
        random.nextBytes(bytes);

        // Prepara a chave AES-256 usando KeyUtils.prepareSecretKey
        // final SecretKey aesKey = KeyUtils.prepareSecretKey(WSConstants.AES_256, bytes);
        final SecretKey aesKey = KeyUtils.prepareSecretKey("AES", bytes);

        // Exibe a chave AES em Base64 (opcional)
        return Base64.getEncoder().encodeToString(aesKey.getEncoded());
    }*/

    public static String generateAes256Key() throws WSSecurityException, NoSuchAlgorithmException {
        // Gerar chave AES-256 efêmera
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Definir o comprimento da chave manualmente para 256 bits (32 bytes)
        final SecretKey aesKey = keyGen.generateKey();

        return Base64.getEncoder().encodeToString(aesKey.getEncoded());
    }

    public static Crypto loadCrypto(
            final String keystorePassword,
            final String keyAlias,
            final String keystorePath
    ) throws Exception {
        Properties cryptoProps = new Properties();
        cryptoProps.put("org.apache.wss4j.crypto.merlin.keystore.type", "jks");
        cryptoProps.put("org.apache.wss4j.crypto.merlin.keystore.password", keystorePassword);
        cryptoProps.put("org.apache.wss4j.crypto.merlin.keystore.alias", keyAlias);
        cryptoProps.put("org.apache.wss4j.crypto.merlin.file", keystorePath);
        return CryptoFactory.getInstance(cryptoProps);
    }

    public static Document initWss4jConfiguration(
            // final String docStr,
            final Document doc,
            final String username,
            final String password
    ) throws WSSecurityException {

        // Initialize WSS4J configuration
        WSSConfig.init();
        // WSSecHeader secHeader = new WSSecHeader(doc); // *********************
        WSSecHeader secHeader = new WSSecHeader();
        // secHeader.insertSecurityHeader(); // *************************
        // secHeader.insertSecurityHeader(doc);

        System.out.println("@@@@@@@@@ nodeToString(doc): @@@@@@@@@");
        System.out.println(nodeToString(doc));
        System.out.println("@@@@@@@@@@@@@@@@@@");

        // Caso o nó de secHeader esteja sendo criado em outro documento, você pode importá-lo assim:
        Document ownerDocument = doc.getOwnerDocument();
        System.out.println("@@@@@@@@@ ownerDocument: @@@@@@@@@");
        System.out.println(nodeToString(ownerDocument));
        System.out.println("@@@@@@@@@@@@@@@@@@");

        final var sh = secHeader.getSecurityHeader();
        System.out.println("@@@@@@@@@ sh: @@@@@@@@@");
        System.out.println(sh);
        System.out.println("@@@@@@@@@@@@@@@@@@");

        final var importedNode = ownerDocument.importNode(sh, true);  // true para importar recursivamente
        // Depois, insira o nó importado no documento correto
        ownerDocument.getDocumentElement().appendChild(importedNode);

        System.out.println("@@@@@@@@@@@@@@@@@@");
        System.out.println("OK");
        System.out.println("@@@@@@@@@@@@@@@@@@");

        return ownerDocument;
/*
        // *********************************** Eu adicionei isso
        final var wssConfig = WSSConfig.getNewInstance();
        // ***********************************

        // Add timestamp
        // WSSecTimestamp timestamp = new WSSecTimestamp(secHeader); // ***********************
        WSSecTimestamp timestamp = new WSSecTimestamp(wssConfig);
        timestamp.setTimeToLive(300); // 5 minutes
        // timestamp.build(); // **********************
        timestamp.build(doc, secHeader);

        // WSSecUsernameToken usernameToken = new WSSecUsernameToken(secHeader); // *******************
        WSSecUsernameToken usernameToken = new WSSecUsernameToken(wssConfig);
        usernameToken.setPasswordType(WSConstants.PW_TEXT);
        usernameToken.setUserInfo(username, password);
        //usernameToken.setPasswordType(null);
        // usernameToken.build(); // ****************
        usernameToken.build(doc, secHeader);*/
    }

    // move this to a DOMUtils class
    private static String nodeToString(final Node node) {
        try {
            final StringWriter writer = new StringWriter();
            final Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
            transformer.transform(new DOMSource(node), new StreamResult(writer));
            return writer.toString();
        } catch (Exception e) {
            System.out.println(" Redeban convert node to String error: " + e.getMessage());
            return null;
        }
    }
}
