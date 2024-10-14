package com.liquido.mvp.utils;

import java.io.StringWriter;
import java.security.cert.X509Certificate;
import java.util.*;

import org.apache.wss4j.dom.util.WSSecurityUtil;
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
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
/*import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;*/
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.message.WSSecUsernameToken;

import java.security.NoSuchAlgorithmException;

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
        cryptoProps.put("org.apache.wss4j.crypto.merlin.file", keystorePath);
        cryptoProps.put("org.apache.wss4j.crypto.merlin.keystore.password", keystorePassword);
        cryptoProps.put("org.apache.wss4j.crypto.merlin.keystore.alias", keyAlias);
        return CryptoFactory.getInstance(cryptoProps);
    }

    private static Document encryptWithWss4j(
            final Crypto crypto,
            final Document doc,
            final String username,
            final String password,
            final WSSecHeader secHeader,
            final String serverCertAlias
    ) throws WSSecurityException {

        // *************************************
        final var header = (Element) doc.getElementsByTagName("soap-env:Header").item(0);

        final var secHeaderElement = (Element) header.getElementsByTagName("wsse:Security").item(0);
        secHeaderElement.removeAttribute("xmlns:wsse");
        secHeaderElement.removeAttribute("xmlns:wsu");
        // *************************************


        // ****************** Configuring Username and Password
        WSSecUsernameToken usernameToken = new WSSecUsernameToken(secHeader); // *******************
        usernameToken.setPasswordType(WSConstants.PW_TEXT);
        usernameToken.setUserInfo(username, password);
        //usernameToken.setPasswordType(null);
        usernameToken.build(); // ****************

        System.out.println("\n############# ADDED Sec Header [ SOAP ENVELOP CLEAN ]: ###############");
        System.out.println(nodeToString(doc));
        System.out.println("############################");


        // ****************************************
        // TODO: move the code snippet below to separated method ???????????????? **************************************************
        // Encrypt the SOAP message
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo(serverCertAlias); // "server"
        encrypt.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER); // China Team
        // encrypt.setSymmetricEncAlgorithm(WSConstants.AES_256); // China Team
        encrypt.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES); // BR Team
        encrypt.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSA15); // China team

        // encrypt.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOAEP);  // Algoritmo RSA-OAEP-MGF1 (BR Team)
        // TODO: testar // encrypt.setUseThisCert(serverCert);
        // TODO: testar // encrypt.setUseThisPublicKey(serverCert.getPublicKey());



        // ---------------------------------------------------------------------------------
        // ----------------------------------- ENCRYPTION ----------------------------------
        // ---------------------------------------------------------------------------------
        // 1) Encrypting the body content
        WSEncryptionPart encP = new WSEncryptionPart(
                "Body", WSConstants.URI_SOAP11_ENV, "Content"
        );

        // Defina o namespace de criptografia XML
        // encP.setEncModifier(WSConstants.ENC_NS); // Gervásio ********************************

        List<WSEncryptionPart> encParts = new ArrayList<>();
        encParts.add(encP);

        encrypt.getParts().addAll(encParts); // ***************************


        // KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_256); // China Team
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES); // BR Team
        SecretKey symmetricKey = keyGen.generateKey(); // **************** Ephemeral Key


        encrypt.build(crypto, symmetricKey); // ***************************


        // *************************************
        System.out.println(header.getElementsByTagName("xenc:EncryptedKey").getLength());
        System.out.println(secHeaderElement.getElementsByTagName("xenc:EncryptedKey").getLength());

        final var encryptedKeyElm = (Element) secHeaderElement.getElementsByTagName("xenc:EncryptedKey").item(0);
        encryptedKeyElm.removeAttribute("Id");

        final var encryptionMethodElm = (Element) encryptedKeyElm.getElementsByTagName("xenc:EncryptionMethod").item(0);
        encryptionMethodElm.setAttribute("xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#");

        final var cipherDataElm = (Element) encryptedKeyElm.getElementsByTagName("xenc:CipherData").item(0);
        cipherDataElm.setAttribute("xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#");

        final var keyInfoHeaderElm = (Element) encryptedKeyElm.getElementsByTagName("ds:KeyInfo").item(0);
        keyInfoHeaderElm.setPrefix("dsig");
        keyInfoHeaderElm.removeAttribute("xmlns:ds");

        final var refList = (Element) encryptedKeyElm.getElementsByTagName("xenc:ReferenceList").item(0);
        final var dataReference = (Element) refList.getElementsByTagName("xenc:DataReference").item(0);
        dataReference.setAttribute("URI", "#body");

        final var usernameTokenElm = (Element) secHeaderElement.getElementsByTagName("wsse:UsernameToken").item(0);
        usernameTokenElm.removeAttribute("xmlns:wsu");
        usernameTokenElm.removeAttribute("wsu:Id");
        final var passwordElm = (Element) usernameTokenElm.getElementsByTagName("wsse:Password").item(0);
        passwordElm.removeAttribute("Type");
        // *************************************


        // ***************** Removing KeyInfo tag from Body tag
        Element soapBody = (Element) doc.getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/", "Body").item(0);
        // Find KeyInfo element from SOAP Body
        NodeList keyInfoNodes = soapBody.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyInfo");
        // Foreach nodes and remove KeyInfo element
        for (int i = keyInfoNodes.getLength() - 1; i >= 0; i--) {
            Node keyInfoNode = keyInfoNodes.item(i);
            keyInfoNode.getParentNode().removeChild(keyInfoNode);
        }


        // ******************************
        /*soapBody.setAttribute("xmlns:ns15", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
        soapBody.setAttribute("ns15:Id", "id-4f5036d7-4c08-45ab-a484-7ce5411d097e");*/
        final var encryptedDataElm = (Element) soapBody.getElementsByTagName("xenc:EncryptedData").item(0);
        encryptedDataElm.setAttribute("Id", "body");
        // ******************************

        return doc;
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

    private static Document signWithWss4j(
            final Crypto crypto,
            final String keyAlias,
            final String clientKeystorePassword,
            final Document doc,
            final WSSecHeader secHeader
    ) throws WSSecurityException {

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
        sign.setSigCanonicalization(WSConstants.C14N_EXCL_WITH_COMMENTS); // **** Canonicalization
        sign.setSignatureAlgorithm(WSConstants.RSA_SHA512);
        sign.setDigestAlgo(WSConstants.SHA512);

        List<WSEncryptionPart> parts = new ArrayList<>();
        parts.add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, ""));
        parts.add(new WSEncryptionPart("Body", WSConstants.URI_SOAP11_ENV, ""));

        // parts.add(new WSEncryptionPart("Envelope", WSConstants.URI_SOAP11_ENV, ""));

        sign.getParts().addAll(parts);
        sign.setAddInclusivePrefixes(false);

        sign.prepare(crypto);
        List<javax.xml.crypto.dsig.Reference> referenceList =
                sign.addReferencesToSign(sign.getParts());
        sign.computeSignature(referenceList, false, null);

        // return nodeToString(doc);
        return doc;
    }

    public static String runWss4jEncryptionAndSignature(
            final Crypto crypto,
            final String serverKeystoreAlias,
            final String clientKeystoreAlias,
            final String keystorePassword,
            final Document doc,
            final String username,
            final String password,
            final boolean encryptAndSign
    ) throws WSSecurityException {

        // Initialize WSS4J configuration
        WSSConfig.init();
        WSSecHeader secHeader = new WSSecHeader(doc); // *********************
        secHeader.insertSecurityHeader(); // *************************

        final var encryptedDoc = encryptWithWss4j(crypto, doc, username, password, secHeader, serverKeystoreAlias);

        System.out.println("\n############# ONLY ENCRYPTED SOAP ENVELOP: ###############");
        System.out.println(nodeToString(encryptedDoc));
        System.out.println("############################");

        if (!encryptAndSign) {
            return nodeToString(encryptedDoc);
        }

        final var signedDoc = signWithWss4j(crypto, clientKeystoreAlias, keystorePassword, encryptedDoc, secHeader);

        System.out.println("\n############# ENCRYPTED AND SIGNED SOAP ENVELOP: ###############");
        System.out.println(nodeToString(signedDoc));
        System.out.println("############################");

        return nodeToString(signedDoc);
    }

    public static String runWss4jEncryptionAndSignature_CN(
            final String keystorePath,
            final String serverKeystoreAlias,
            final String clientKeystoreAlias,
            final String keystorePassword,
            final Document doc,
            final boolean encryptAndSign
    ) throws Exception {

        // Loading the server Crypto properties
        final var crypto = Wss4jUtils.loadCrypto(
                keystorePassword,
                clientKeystoreAlias, // client alias ****
                keystorePath);

        // Initialize WSS4J configuration
        WSSConfig.init();
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        // Add timestamp
        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300); // 5 minutes
        timestamp.build();

        WSSecUsernameToken usernameToken = new WSSecUsernameToken(secHeader);
        usernameToken.setPasswordType(WSConstants.PW_TEXT);
        usernameToken.setUserInfo(RedebanUtils.WSSEC_AUTH_USERNAME, RedebanUtils.WSSEC_AUTH_PASSWORD);
        //usernameToken.setPasswordType(null);
        usernameToken.build();

        System.out.println("############# Added some Sec Header fields: ###############");
        System.out.println(nodeToString(doc));
        System.out.println("############################");

        // Encrypt the SOAP message
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo(serverKeystoreAlias); // ***********
        encrypt.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        encrypt.setSymmetricEncAlgorithm(WSConstants.AES_256);
        encrypt.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSA15); // **********
        // Encrypt the body
        WSEncryptionPart encP = new WSEncryptionPart(
                "Body", WSConstants.URI_SOAP11_ENV, "Content"
        );
        List<WSEncryptionPart> encParts = new ArrayList<>();
        encParts.add(encP);
        encrypt.getParts().addAll(encParts);
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_256);
        SecretKey symmetricKey = keyGen.generateKey();
        encrypt.build(crypto, symmetricKey);

        // Remove keyInfo
        Element soapbody = (Element) doc.getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/", "Body").item(0);
        // Find KeyInfo element from SOAP Body
        NodeList keyInfoNodes = soapbody.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyInfo");
        // Foreach nodes and remove KeyInfo element
        for (int i = keyInfoNodes.getLength() - 1; i >= 0; i--) {
            Node keyInfoNode = keyInfoNodes.item(i);
            keyInfoNode.getParentNode().removeChild(keyInfoNode);
        }

        System.out.println("############# ONLY ENCRYPTED ###############");
        System.out.println(nodeToString(doc));
        System.out.println("############################");

        if (!encryptAndSign) {
            return nodeToString(doc);
        }

        //Sign the SOAP message
        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setUserInfo(clientKeystoreAlias, keystorePassword); // **********
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

        final var signedEncryption = nodeToString(doc);
        System.out.println("############# ENCRYPTED AND SIGNED: ###############");
        System.out.println(signedEncryption);
        System.out.println("############################");
        return signedEncryption;
    }

    public static String runWss4jEncryptionAndSignature_BR(
            final String keystorePath,
            final String serverKeystoreAlias,
            final String clientKeystoreAlias,
            final String keystorePassword,
            final Document soapDocument,
            final boolean encryptAndSign
    ) throws Exception {

        // ************************************
        // Loading the server Crypto properties
        final var serverCrypto = Wss4jUtils.loadCrypto(
                keystorePassword,
                serverKeystoreAlias,
                keystorePath);
        System.out.println("@@@@@@@ serverCrypto loaded @@@@@@@");
        System.out.println(serverCrypto.getDefaultX509Identifier());
        // ************************************


        // Cria o cabeçalho de segurança:
        WSSecHeader secHeader = new WSSecHeader(soapDocument);
        secHeader.insertSecurityHeader();

        final var encryptedDoc = encryptWithWss4j_BR(serverCrypto, soapDocument, serverKeystoreAlias, secHeader);

        System.out.println("\n############# ONLY ENCRYPTED SOAP ENVELOP: ###############");
        System.out.println(nodeToString(encryptedDoc));
        System.out.println("############################");

        if (!encryptAndSign) {
            return nodeToString(encryptedDoc);
        }


        // ************************************
        // Loading the client Crypto properties
        final var clientCrypto = Wss4jUtils.loadCrypto(
                keystorePassword,
                clientKeystoreAlias,
                keystorePath);

        System.out.println("@@@@@@@ clientCrypto loaded @@@@@@@");
        System.out.println(clientCrypto.getDefaultX509Identifier());
        // ************************************

        // return "Signature not implemented yet!!!";

        // for sign: https://stackoverflow.com/questions/56701257/wsse-sign-an-element-inside-soapenvheader

        final var signedDoc = signWithWss4j_BR(clientCrypto, clientKeystoreAlias, keystorePassword, encryptedDoc, secHeader);

        System.out.println("\n############# ENCRYPTED AND SIGNED SOAP ENVELOP: ###############");
        System.out.println(nodeToString(signedDoc));
        System.out.println("############################");

        return nodeToString(signedDoc);
    }

    private static Document encryptWithWss4j_BR(
            final Crypto serverCrypto,
            final Document soapMessage,
            final String serverCertAlias,
            final WSSecHeader secHeader
    ) throws Exception {

        // TODO: - checar o que faz o método encrypt.setEncryptedKeyElement?

        // TODO: - garantir SOMENTE O CONTEÚDO DENTRO DA TAG BODY DEVE SER CIFRADO;



        // ######################################################
        System.out.println("serverCrypto.getDefaultX509Identifier() - alias: " + serverCrypto.getDefaultX509Identifier());

        // Cria um objeto CryptoType para buscar o certificado público do servidor pelo alias ("server" in Dev/Test Environmnet)
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias(serverCertAlias); // ("server" in Dev/Test Environmnet)

        // Obtém o certificado público do servidor
        X509Certificate[] serverCerts = serverCrypto.getX509Certificates(cryptoType);
        if (serverCerts == null || serverCerts.length == 0) {
            throw new Exception("Certificado público do servidor não encontrado no keystore.");
        }

        X509Certificate serverCert = serverCerts[0];
        System.out.println("@@@@@@@@@@@@@@ serverCert found: " + serverCert);

        // Obtém o valor do Subject Key Identifier (OID 2.5.29.14)
        byte[] ski = serverCert.getExtensionValue("2.5.29.14");
        if (ski != null) {
            System.out.println("Subject Key Identifier (SKI) encontrado no certificado.");
            System.out.println("Valor do SKI: " + Arrays.toString(ski));
        } else {
            System.out.println("Subject Key Identifier (SKI) NÃO encontrado no certificado.");
        }
        // ######################################################





        // ######################### INÍCIO DA CIFRAGEM DO BODY E DA CHAVE EFÊMERA #############################

        WSSConfig.init();


        WSSecUsernameToken usernameToken = new WSSecUsernameToken(secHeader);
        usernameToken.setPasswordType(WSConstants.PW_TEXT);
        usernameToken.setUserInfo(RedebanUtils.WSSEC_AUTH_USERNAME,
                RedebanUtils.WSSEC_AUTH_PASSWORD);
        //usernameToken.setPasswordType(null);
        usernameToken.build();

        // Configura o WS-Security para criptografia:
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);


        // 1)
        // - Gera uma chave simétrica temporária (efêmera)
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_256);
        SecretKey symmetricKey = keyGen.generateKey();
        /*
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);  // Tamanho da chave de 256 bits
        SecretKey symmetricKey = keyGen.generateKey();  // Chave simétrica efêmera*/
        // *****************************


        // 2) Criptografia Simétrica:
        // - Cifrar o conteúdo do Body (com a chave efêmera e o algoritmo AES-256-CBC)

        // Define o algoritmo de criptografia simétrica para AES-256-CBC:
        encrypt.setSymmetricEncAlgorithm(WSConstants.AES_256); // Algoritmo de criptografia simétrica (AES-256-CBC)
        /*
        * Em relação ao vetor de inicialização (IV), utilizado pelo modo CBC,
        * a lib wss4j também o cifra, a chave efêmera, utilizando a chave pública do server.
        *
        * TODO: procurar saber se a lib concatena a chave e o IV antes de cifrá-los.
        * */


        // 3)
        // Criptografia Assimétrica:
        // - Cifrar a chave efêmera (com a chave pública da Redeban e o algoritmo RSA-OAEP-MGF1)

        // Define o alias do certificado público da Redeban
        /*
         * Este método é usado para definir um alias que será utilizado para buscar o certificado correspondente em um keystore.
         * Ao usar setUserInfo(...), você está indicando que deseja usar um certificado associado a esse alias
         * para a Cifragem da Chave Simétrica (Criptografia Assimétrica).
         * */
        encrypt.setUserInfo(serverCertAlias); // "server" alias *******************

        // ************
        /*
         * Este método aceita um objeto do tipo X509Certificate.
         * Ele extrai a chave pública desse certificado e a utiliza para Cifrar a Chave Simétrica.
         * Você ainda pode acessar outras informações do certificado, como a identidade do destinatário, caso necessário.
         * */
        // encrypt.setUseThisCert(serverCert);

        /*
         * Este método permite que você forneça diretamente um objeto PublicKey.
         * Ao fazer isso, você está explicitamente informando que deseja usar essa chave pública para a cifragem, eliminando a necessidade de buscar um certificado a partir de um alias.
         * Se você já está fornecendo a chave pública, não é necessário especificar um alias ou buscar informações de um keystore.
         * */
        // encrypt.setUseThisPublicKey(serverCert.getPublicKey());
        // O uso dos métodos setUseThisCert e setUseThisPublicKey acima dispensa o uso do encrypt.setUserInfo
        // ************

        // *************** SKI ***************
        // Define o identificador da chave pública (RSA):
        encrypt.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        /*if (ski != null) {
            encrypt.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        } else {
            encrypt.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        }*/


        // Define o algoritmo assimétrico de transporte de chave para RSA-OAEP-MGF1:
        encrypt.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOAEP);  // Algoritmo RSA-OAEP-MGF1
        // TODO: observar que o valor da constante WSConstants.KEYTRANSPORT_RSAOAEP não corresponde ao valor exato que está no arquivo cifrado.xml.



        // @@@@@@@@@@@@@ SOMENTE O CONTEÚDO DENTRO DA TAG BODY ESTÁ SENDO CIFRADO
        // Encrypt the body
        WSEncryptionPart encP = new WSEncryptionPart(
                "Body", WSConstants.URI_SOAP11_ENV, "Content"
        );
        List<WSEncryptionPart> encParts = new ArrayList<>();
        encParts.add(encP);
        encrypt.getParts().addAll(encParts);
        // ******************************


        encrypt.build(serverCrypto, symmetricKey);

        // Remove keyInfo from body
        Element soapbody = (Element) soapMessage
                .getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/", "Body").item(0);
        // Find KeyInfo element from SOAP Body
        NodeList keyInfoNodes = soapbody
                .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyInfo");
        // Foreach nodes and remove KeyInfo element
        for (int i = keyInfoNodes.getLength() - 1; i >= 0; i--) {
            Node keyInfoNode = keyInfoNodes.item(i);
            keyInfoNode.getParentNode().removeChild(keyInfoNode);
        }

        return soapMessage;
    }

    private static Document signWithWss4j_BR(
            final Crypto crypto,
            final String keyAlias,
            final String clientKeystorePassword,
            final Document doc,
            final WSSecHeader secHeader
    ) throws WSSecurityException {


        // ---------------------------------------------------------------------------------
        // ----------------------------------- SIGNATURE -----------------------------------
        // ---------------------------------------------------------------------------------
        // 2) Sign the SOAP message
        WSSecSignature sign = new WSSecSignature(secHeader);

        sign.setUserInfo(keyAlias, clientKeystorePassword);

        sign.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
        sign.setSigCanonicalization(WSConstants.C14N_EXCL_WITH_COMMENTS); // **** Canonicalization
        sign.setSignatureAlgorithm(WSConstants.RSA_SHA512);
        sign.setDigestAlgo(WSConstants.SHA512);

        // #######################################################
        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader); // ***********************
        // WSSecTimestamp timestamp = new WSSecTimestamp(wssConfig);
        timestamp.setTimeToLive(300); // 5 minutes
        timestamp.build(); // **********************
        // #######################################################

        List<WSEncryptionPart> parts = new ArrayList<>();
        parts.add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, ""));
        parts.add(new WSEncryptionPart("Body", WSConstants.URI_SOAP11_ENV, ""));

        // parts.add(new WSEncryptionPart("Envelope", WSConstants.URI_SOAP11_ENV, ""));

        sign.getParts().addAll(parts);
        sign.setAddInclusivePrefixes(false);

        sign.prepare(crypto);
        List<javax.xml.crypto.dsig.Reference> referenceList =
                sign.addReferencesToSign(sign.getParts());
        sign.computeSignature(referenceList, false, null);

        // return nodeToString(doc);
        return doc;
    }
}
