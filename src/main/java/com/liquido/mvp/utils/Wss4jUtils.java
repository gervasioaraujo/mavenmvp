package com.liquido.mvp.utils;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.dom.engine.WSSConfig; // *************
// import org.apache.wss4j.dom.WSSConfig;
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

    public static String runWss4jEncryption(
            final Crypto crypto,
            final String keyAlias,
            final String clientKeystorePassword,
            final Document doc,
            final String username,
            final String password
    ) throws WSSecurityException {

        // Initialize WSS4J configuration
        WSSConfig.init();
        WSSecHeader secHeader = new WSSecHeader(doc); // *********************
        secHeader.insertSecurityHeader(); // *************************

        // ****************** Configuring Username and Password
        WSSecUsernameToken usernameToken = new WSSecUsernameToken(secHeader); // *******************
        usernameToken.setPasswordType(WSConstants.PW_TEXT);
        usernameToken.setUserInfo(username, password);
        //usernameToken.setPasswordType(null);
        usernameToken.build(); // ****************

        System.out.println("\n############# ADDED Sec Header to SOAP ENVELOP: ###############");
        System.out.println(nodeToString(doc));
        System.out.println("############################");


        // ****************************************
        // TODO: move the code snippet below to separated method ???????????????? **************************************************
        // Encrypt the SOAP message
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("server"); // TODO: ??????????????????????????????????????
        encrypt.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        encrypt.setSymmetricEncAlgorithm(WSConstants.AES_256);
        encrypt.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSA15);


        // ---------------------------------------------------------------------------------
        // ----------------------------------- ENCRYPTION ----------------------------------
        // ---------------------------------------------------------------------------------
        // 1) Encrypting the body content
        WSEncryptionPart encP = new WSEncryptionPart(
                "Body", WSConstants.URI_SOAP11_ENV, "Content"
        );
        List<WSEncryptionPart> encParts = new ArrayList<>();
        encParts.add(encP);

        encrypt.getParts().addAll(encParts); // ***************************


        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_256);
        SecretKey symmetricKey = keyGen.generateKey(); // **************** Ephemeral Key


        encrypt.build(crypto, symmetricKey); // ***************************


        // ***************** Removing KeyInfo tag from Body tag
        Element soapBody = (Element) doc.getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/", "Body").item(0);
        // Find KeyInfo element from SOAP Body
        NodeList keyInfoNodes = soapBody.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyInfo");
        // Foreach nodes and remove KeyInfo element
        for (int i = keyInfoNodes.getLength() - 1; i >= 0; i--) {
            Node keyInfoNode = keyInfoNodes.item(i);
            keyInfoNode.getParentNode().removeChild(keyInfoNode);
        }

        final var encryptedSOAPEnvelop = nodeToString(doc);
        /*System.out.println("\n############# ENCRYPTED SOAP ENVELOP: ###############");
        System.out.println(encryptedSOAPEnvelop);
        System.out.println("############################");*/

        // #######################################################
        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader); // ***********************
        // WSSecTimestamp timestamp = new WSSecTimestamp(wssConfig);
        timestamp.setTimeToLive(300); // 5 minutes
        timestamp.build(); // **********************




        /*// 2) Sign the SOAP message
        WSSecSignature sign = new WSSecSignature(secHeader);

        sign.setUserInfo(keyAlias, clientKeystorePassword);

        sign.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
        sign.setSigCanonicalization(WSConstants.C14N_EXCL_WITH_COMMENTS);
        sign.setSignatureAlgorithm(WSConstants.RSA_SHA512);
        sign.setDigestAlgo(WSConstants.SHA512);
        List<WSEncryptionPart> parts = new ArrayList<>();
        parts.add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, ""));
        parts.add(new WSEncryptionPart("Body", WSConstants.URI_SOAP11_ENV, ""));
        sign.getParts().addAll(parts);
        sign.setAddInclusivePrefixes(false);

        sign.prepare(crypto);
        List<javax.xml.crypto.dsig.Reference> referenceList =
                sign.addReferencesToSign(sign.getParts());
        sign.computeSignature(referenceList, false, null);

        final var signedSOAPEnvelop = nodeToString(doc);
        System.out.println("\n############# SIGNED SOAP ENVELOP: ###############");
        System.out.println(signedSOAPEnvelop);
        System.out.println("############################");
        // return signedEncryption;*/

        return encryptedSOAPEnvelop;
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

    public static String runWss4jEncryptionAndSignature(
            final Crypto crypto,
            final String keyAlias,
            final String clientKeystorePassword,
            final Document doc,
            final String username,
            final String password
    ) throws WSSecurityException {

        // Initialize WSS4J configuration
        WSSConfig.init();
        WSSecHeader secHeader = new WSSecHeader(doc); // *********************
        secHeader.insertSecurityHeader(); // *************************

        // ****************** Configuring Username and Password
        WSSecUsernameToken usernameToken = new WSSecUsernameToken(secHeader); // *******************
        usernameToken.setPasswordType(WSConstants.PW_TEXT);
        usernameToken.setUserInfo(username, password);
        //usernameToken.setPasswordType(null);
        usernameToken.build(); // ****************


        System.out.println("\n############# ADDED Sec Header to SOAP ENVELOP: ###############");
        System.out.println(nodeToString(doc));
        System.out.println("############################");


        // ****************************************
        // TODO: move the code snippet below to separated method ???????????????? **************************************************
        // Encrypt the SOAP message
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("server");
        encrypt.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        encrypt.setSymmetricEncAlgorithm(WSConstants.AES_256);
        encrypt.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSA15);


        // ---------------------------------------------------------------------------------
        // ----------------------------------- ENCRYPTION ----------------------------------
        // ---------------------------------------------------------------------------------
        // 1) Encrypt the body
        WSEncryptionPart encP = new WSEncryptionPart(
                "Body", WSConstants.URI_SOAP11_ENV, "Content"
        );
        List<WSEncryptionPart> encParts = new ArrayList<>();
        encParts.add(encP);


        encrypt.getParts().addAll(encParts);


        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_256);
        SecretKey symmetricKey = keyGen.generateKey(); // **************** Ephemeral Key


        encrypt.build(crypto, symmetricKey);


        // ***************** Removing KeyInfo tag from Body tag
        Element soapBody = (Element) doc.getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/", "Body").item(0);
        // Find KeyInfo element from SOAP Body
        NodeList keyInfoNodes = soapBody.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyInfo");
        // Foreach nodes and remove KeyInfo element
        for (int i = keyInfoNodes.getLength() - 1; i >= 0; i--) {
            Node keyInfoNode = keyInfoNodes.item(i);
            keyInfoNode.getParentNode().removeChild(keyInfoNode);
        }

        final var encryptedSOAPEnvelop = nodeToString(doc);
        /*System.out.println("\n############# ENCRYPTED SOAP ENVELOP: ###############");
        System.out.println(encryptedSOAPEnvelop);
        System.out.println("############################");*/

        // #######################################################
        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader); // ***********************
        // WSSecTimestamp timestamp = new WSSecTimestamp(wssConfig);
        timestamp.setTimeToLive(300); // 5 minutes
        timestamp.build(); // **********************


        // ---------------------------------------------------------------------------------
        // ----------------------------------- SIGNATURE -----------------------------------
        // ---------------------------------------------------------------------------------
        // 2) Sign the SOAP message
        WSSecSignature sign = new WSSecSignature(secHeader);

        sign.setUserInfo(keyAlias, clientKeystorePassword);

        sign.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
        sign.setSigCanonicalization(WSConstants.C14N_EXCL_WITH_COMMENTS);
        sign.setSignatureAlgorithm(WSConstants.RSA_SHA512);
        sign.setDigestAlgo(WSConstants.SHA512);
        List<WSEncryptionPart> parts = new ArrayList<>();
        parts.add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, ""));
        parts.add(new WSEncryptionPart("Body", WSConstants.URI_SOAP11_ENV, ""));
        sign.getParts().addAll(parts);
        sign.setAddInclusivePrefixes(false);

        sign.prepare(crypto);
        List<javax.xml.crypto.dsig.Reference> referenceList =
                sign.addReferencesToSign(sign.getParts());
        sign.computeSignature(referenceList, false, null);

        return nodeToString(doc);
        // final var signedSOAPEnvelop = nodeToString(doc);
        /*System.out.println("\n############# SIGNED SOAP ENVELOP: ###############");
        System.out.println(signedSOAPEnvelop);
        System.out.println("############################");*/
        // return signedEncryption;

        // return signedSOAPEnvelop;
    }
}
