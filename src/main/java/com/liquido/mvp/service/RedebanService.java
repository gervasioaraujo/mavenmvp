package com.liquido.mvp.service;

import java.io.*;

import com.liquido.mvp.utils.Wss4jUtils;
import com.liquido.mvp.utils.RedebanUtils;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import java.nio.charset.StandardCharsets;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.net.ssl.*;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

// import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class RedebanService {

    /**
     * Path to the client keystore
     */
    private final String KEYSTORE_PATH = "keystore.jks";
    /**
     * Password for the client keystore
     */
    private final String KEYSTORE_PASSWORD = "liquido123";
    /**
     * The client's alias within the client keystore.
     */
    private final String CLIENT_KEYSTORE_ALIAS = "liauidoTest";
    /**
     * The server certificate's alias within the client keystore.
     */
    private final String SERVER_KEYSTORE_ALIAS = "server";

    private final String SERVER_SECURE_PORT = "9990";

    // private final String SERVER_UNSECURE_PORT = "443";


    // Função para converter bytes em formato PEM legível
    private static String convertToPem(byte[] keyBytes, String description) {
        StringWriter writer = new StringWriter();
        writer.write("-----BEGIN " + description + "-----\n");
        writer.write(Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(keyBytes));
        writer.write("\n-----END " + description + "-----\n");
        return writer.toString();
    }

    /*
     * https://gist.github.com/benleov/292fb7ee692e830f5dd1
     * */
    // private SSLContext initMutualTlsHandshake() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
    private void initMutualTlsHandshake() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {

        /*
         * Load the keystore
         */
        char[] password = KEYSTORE_PASSWORD.toCharArray();
        KeyStore keystore = loadKeystore(password);

        // ####################################################################
        /*System.out.println("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Checking keystore.jks file... @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
        // Obtém todas as entradas do keystore
        Enumeration<String> aliases = keystore.aliases();
        // Itera sobre as entradas e extrai certificados
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            System.out.println("\n************ alias: ****************");

            // #########################################################
            *//*if (alias.equals(CLIENT_KEYSTORE_ALIAS.toLowerCase())) {
                alias = CLIENT_KEYSTORE_ALIAS;
            }*//*
            // #########################################################
            System.out.println(alias);

            if (keystore.isCertificateEntry(alias)) {
                Certificate cert = keystore.getCertificate(alias);
                System.out.println("Certificado encontrado para o alias: " + alias);
                System.out.println(cert);
            }  else if (keystore.isKeyEntry(alias)) {
                Certificate[] chain = keystore.getCertificateChain(alias);
                if (chain != null) {
                    System.out.println("Certificado(s) associado(s) ao alias " + alias + ":");
                    for (Certificate cert : chain) {
                        System.out.println(cert);

                        PublicKey publicKey = cert.getPublicKey();
                        System.out.println("Chave Pública: " + publicKey);

                        // Exibe a chave pública em formato PEM (Base64)
                        String publicKeyPem = convertToPem(cert.getPublicKey().getEncoded(), "PUBLIC KEY");
                        System.out.println("Chave Pública (formato PEM):\n" + publicKeyPem);
                    }

                    // Obtém a chave privada
                    PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, CLIENT_KEYSTORE_PASSWORD.toCharArray());

                    // Exibe a chave privada em formato PEM (Base64)
                    String privateKeyPem = convertToPem(privateKey.getEncoded(), "PRIVATE KEY");
                    System.out.println("Chave Privada (formato PEM):\n" + privateKeyPem);
                } else {
                    System.out.println("Nenhum certificado associado à chave privada do alias " + alias);
                }
            } else if (keystore.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
                System.out.println("Alias " + alias + " contém uma chave secreta.");
            } else {
                System.out.println("Alias " + alias + " é de tipo desconhecido.");
            }
            System.out.println("****************************\n");
        }
        System.out.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");*/
        // ####################################################################

        /*
         * Get the servers trusted certificate.
         */
        final Certificate trusted = keystore
                .getCertificate(SERVER_KEYSTORE_ALIAS);

        /*
         * Create a trust manager that validates the servers certificate
         */
        TrustManager[] trustManager = new TrustManager[] { new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs,
                                           String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs,
                                           String authType) throws CertificateException {

                if (certs == null || certs.length == 0) {
                    throw new IllegalArgumentException(
                            "null or zero-length certificate chain");
                }

                // if (authType == null || authType.length() == 0) {
                if (authType == null || authType.isEmpty()) {
                    throw new IllegalArgumentException(
                            "null or zero-length authentication type");
                }

                System.out.println("\n****************************");
                System.out.println("certs.length: " + certs.length);
                System.out.println("****************************");

                for (X509Certificate cert : certs) {
                    System.out.println("\n************ received serverCert: ****************");
                    System.out.println("serverCert.getPublicKey(): " + cert.getPublicKey());
                    System.out.println("serverCert.getType(): " + cert.getType());
                    System.out.println("Subject: " + cert.getSubjectDN());
                    System.out.println("serverCert.getIssuerDN(): " + cert.getIssuerDN());
                    System.out.println("Serial Number: " + cert.getSerialNumber());
                    System.out.println("serverCert.getIssuerX500Principal(): " + cert.getIssuerX500Principal());
                    System.out.println("****************************");
                }

                final var serverCert = certs[0]; // ***************************************

                System.out.println("\n************ trusted: ****************");
                System.out.println("trusted.getPublicKey(): " + trusted.getPublicKey());
                System.out.println("trusted.getType(): " + trusted.getType());
                System.out.println("****************************");

                // check if certificate sent is your CA's
                if (!serverCert.equals(trusted)) {

                    // check if its been signed by the CA

                    try {
                        serverCert.verify(trusted.getPublicKey());
                    } catch (InvalidKeyException | NoSuchAlgorithmException
                             | NoSuchProviderException | SignatureException e) {
                        throw new CertificateException(e);
                    }
                }

                serverCert.checkValidity();
            }
        } };

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
                .getDefaultAlgorithm());

        kmf.init(keystore, password);

        // set the trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(kmf.getKeyManagers(), trustManager,
                new java.security.SecureRandom());

        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        // create an all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        // return sc;
    }

    private KeyStore loadKeystore(char[] password)
            throws NoSuchAlgorithmException, CertificateException, IOException,
            KeyStoreException {

        FileInputStream is = new FileInputStream(new File(KEYSTORE_PATH));

        final KeyStore keystore = KeyStore.getInstance(KeyStore
                .getDefaultType());

        keystore.load(is, password);

        return keystore;
    }


    private String sendSOAPRequest(
            final String xmlSOAPEnvelop,
            final String serverPort
    ) throws IOException {

        System.out.println("2222222222222222222222222");
        // final var xmlSOAPEnvelop = xmlEnvelopEncryptedAndSignedBody;

        // send to the server
        /**
         * URL to our SOAP UI service
         */
        final var SOAP_URI = String.format("https://www.txstestrbm.com:%s/CompraElectronica/Compra", serverPort);
        System.out.printf("Sending request to: %s%n", SOAP_URI);

        URL url = new URL(SOAP_URI);
        URLConnection urlConnection = url.openConnection();
        final var httpsConn = (HttpsURLConnection) urlConnection;



        // ################# Abre a conexão HTTPS
        // HttpsURLConnection httpsConn = (HttpsURLConnection) url.openConnection();
        // httpsConn.connect();

        // Obtém a cadeia de certificados do servidor
        /*Certificate[] certs = httpsConn.getServerCertificates();

        System.out.println("\n\n---------------------------------------------------");
        System.out.println("Cadeia de Certificados do Servidor:");
        for (Certificate cert : certs) {
            X509Certificate x509Cert = (X509Certificate) cert;
            System.out.println("Subject: " + x509Cert.getSubjectDN());
            System.out.println("Issuer: " + x509Cert.getIssuerDN());
            System.out.println("Serial Number: " + x509Cert.getSerialNumber());
            System.out.println("---------------------------------------------------\n\n");
        }*/
        // ###########################################




        byte[] buffer = new byte[xmlSOAPEnvelop.length()];
        buffer = xmlSOAPEnvelop.getBytes();

        System.out.println("33333333333333333333333");

        String SOAPAction = "";
        // Set the appropriate HTTP parameters.
        httpsConn.setRequestProperty("Content-Length", String
                .valueOf(buffer.length));
        httpsConn.setRequestProperty("Content-Type",
                "text/xml; charset=utf-8"); // application/xml
        // x-liquido-service
        // x-liquido-internal-id

        System.out.println("44444444444444444444444");

        httpsConn.setRequestProperty("SOAPAction", SOAPAction);
        httpsConn.setRequestMethod("POST");
        httpsConn.setDoOutput(true);
        httpsConn.setDoInput(true);

        System.out.println("55555555555555555555555");

        OutputStream out = httpsConn.getOutputStream();
        out.write(buffer);
        out.close();


        // Read the response and write it to standard out.
        final var is = httpsConn.getInputStream();
        System.out.println("66666666666666666666666");

        // InputStreamReader isr = new InputStreamReader(httpsConn.getInputStream());
        InputStreamReader isr = new InputStreamReader(is);
        BufferedReader in = new BufferedReader(isr);

        System.out.println("777777777777777777777777");

        String responseString = null;
        String outputString="";
        while ((responseString = in.readLine()) != null)
        {
            outputString = outputString + responseString;
        }

        System.out.println("################# SERVER RESPONSE: ###################");
        System.out.println(outputString);
        System.out.println("####################################");


        return outputString;
    }

    private String extractBodyContent(
            final String basicSOAPEnvelop
    ) throws ParserConfigurationException, IOException, SAXException {

        // Loading xml
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        Document document = factory.newDocumentBuilder().parse(
                new ByteArrayInputStream(basicSOAPEnvelop.getBytes(StandardCharsets.UTF_8)));

        // Get body element
        String bodyContent = null;
        NodeList bodyList = document.getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/", "Body");
        if (bodyList.getLength() > 0) {
            Element bodyElement = (Element) bodyList.item(0);

            // Get body context
            bodyContent = nodeToString(bodyElement.getFirstChild());
            // System.out.println("Extracted Body Content:" + bodyContent);
        } else {
            System.out.println("No Body element found.");
        }

        return bodyContent;
    }

    private String nodeToString(final Node node) {
        try {
            final StringWriter writer = new StringWriter();
            final Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
            transformer.transform(new DOMSource(node), new StreamResult(writer));
            return writer.toString();
        } catch (Exception e) {
            System.out.println("Convert node to String error: " + e.getMessage());
            return null;
        }
    }

    private Document buildSoapXmlDocument(
            final String bodyContent
    ) throws Exception {
        // New soap xml
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();

        // Soap create
        SOAPEnvelope envelope = soapMessage.getSOAPPart().getEnvelope();
        envelope.removeNamespaceDeclaration(envelope.getPrefix());
        envelope.setPrefix("soap-env");
        envelope.addNamespaceDeclaration("soap-env", "http://schemas.xmlsoap.org/soap/envelope/");

        SOAPBody soapBody = envelope.getBody();
        soapBody.setPrefix("soap-env");
        SOAPHeader soapHeader = envelope.getHeader();
        soapHeader.setPrefix("soap-env");
        soapBody.addDocument(convertStringToDocument(bodyContent));

        soapMessage.saveChanges();
        return soapMessageToDocument(soapMessage);
    }

    private Document convertStringToDocument(final String xmlStr) {
        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        try {
            final DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(new InputSource(new StringReader(xmlStr)));
        } catch (Exception e) {
            System.out.println(" Redeban convert String to Document error: " + e.getMessage());
            return null;
        }
    }

    private Document soapMessageToDocument(SOAPMessage soapMessage) throws Exception {
        return soapMessage.getSOAPPart().getEnvelope().getOwnerDocument();
    }


    // WSS4J - 2.4.3 version - BR Team
    public String executeWss4jSOAPAndHttpsRequest_BR(
            final boolean encryptAndSign
    ) throws Exception {

        // 0) mounting basic SOAP envelop

        // ########## Getting basic CLEAN SOAP Envelop with only Body tag ##########
        final var basicCleanSOAPEnvelop = RedebanUtils.getBasicSOAPEnvelopBrazilTeam(); // ******************


        // ########## Extracting CLEAN Body tag (***** only content body) ##########
        final var bodyContent = extractBodyContent(basicCleanSOAPEnvelop);
        // final var bodyContent = RedebanUtils.getBasicCleanSOAPEnvelop();
        // final var bodyContent = RedebanUtils.getCleanBodyContent();
        System.out.println("\n############# INITIAL Extracted bodyContent: ###############");
        System.out.println(bodyContent);
        System.out.println("############################");


        Document soapXmlDocument = buildSoapXmlDocument(bodyContent); // *******************


        System.out.println("\n############# BASIC SOAP ENVELOP - with no Header (soapXmlDocument Str): ###############");
        System.out.println(nodeToString(soapXmlDocument));
        System.out.println("############################");


        // ***************************************************************
        String finalSOAPStr = Wss4jUtils.runWss4jEncryptionAndSignature_BR(
                KEYSTORE_PATH,
                SERVER_KEYSTORE_ALIAS,
                CLIENT_KEYSTORE_ALIAS,
                KEYSTORE_PASSWORD,
                soapXmlDocument,
                encryptAndSign
        );


        // System.out.println("\n############# FINAL SOAP ENVELOP to send to Redeban: ###############");
        /*System.out.println(finalSOAPStr);
        System.out.println("############################");*/

        // final var sc = initMutualTlsHandshake();
        initMutualTlsHandshake();

        /*HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        // create an all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);*/

        return sendSOAPRequest(finalSOAPStr, SERVER_SECURE_PORT);
    }

}
