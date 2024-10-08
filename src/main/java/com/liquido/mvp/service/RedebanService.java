package com.liquido.mvp.service;

import java.io.*;

import com.liquido.mvp.utils.Wss4jUtils;
import com.liquido.mvp.utils.crypto.AESCryptography;
import com.liquido.mvp.utils.RedebanUtils;
import com.liquido.mvp.utils.crypto.RSACryptography;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import java.nio.charset.StandardCharsets;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

// import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.*;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.net.HttpURLConnection;
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
     * Path to the clients keystore
     */
    private final String CLIENT_KEYSTORE_PATH = "keystore.jks";
    /**
     * Password for the clients keystore
     */
    private final String CLIENT_KEYSTORE_PASSWORD = "liquido123";
    /**
     * The servers certificate's alias within the clients keystore.
     */
    private final String SERVER_CERTIFICATE_ALIAS = "liauidoTest";

    /*
     * https://gist.github.com/benleov/292fb7ee692e830f5dd1
     * */
    private SSLContext configureCertificate() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
    // private void configureCertificate() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {

        /*
         * Load the keystore
         */
        char[] password = CLIENT_KEYSTORE_PASSWORD.toCharArray();
        KeyStore keystore = loadKeystore(CLIENT_KEYSTORE_PATH, password);

        /*
         * Get the servers trusted certificate.
         */
        final Certificate trusted = keystore
                .getCertificate(SERVER_CERTIFICATE_ALIAS);

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

                if (authType == null || authType.length() == 0) {
                    throw new IllegalArgumentException(
                            "null or zero-length authentication type");
                }

                // check if certificate sent is your CA's

                if (!certs[0].equals(trusted)) {

                    // check if its been signed by the CA

                    try {
                        certs[0].verify(trusted.getPublicKey());
                    } catch (InvalidKeyException | NoSuchAlgorithmException
                             | NoSuchProviderException | SignatureException e) {
                        throw new CertificateException(e);
                    }
                }

                certs[0].checkValidity();
            }
        } };

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
                .getDefaultAlgorithm());

        kmf.init(keystore, password);

        // set the trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(kmf.getKeyManagers(), trustManager,
                new java.security.SecureRandom());

        return sc;
    }

    private KeyStore loadKeystore(String filePath, char[] password)
            throws NoSuchAlgorithmException, CertificateException, IOException,
            KeyStoreException {

        FileInputStream is = new FileInputStream(new File(filePath));

        final KeyStore keystore = KeyStore.getInstance(KeyStore
                .getDefaultType());

        keystore.load(is, password);

        return keystore;
    }

    public String executeSOAPAndHttpsRequestV1() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, KeyManagementException, SOAPException {

        final var sc = configureCertificate();

        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        /*// create an all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };

        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);*/


        // *****************************************************

        /*
         * 1 - criptografar o xml do body limpo:
         * - encriptar o body com chave efêmera (gerada pela lib wss4j) com AES_256_CBC (example Hekate RedebanRoute: "KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_256);" )
         * - extrair a chave pública do certificado da redeban e encriptar a chave efêmera com essa chave pública.
         * */

        // SOAP body clean
        final var xmlBodyClean = RedebanUtils.getXmlBodyClean();

        // TODO:
        // 1)
        // 1.1) - generate Ephemeral Key;
        final var ephemeralKey = "aesEncryptionKey";

        // 1.2) - encrypt SOAP body clean using Ephemeral Key (with AES-256-CBC);
        final var encryptedSOAPBody = RedebanUtils.encryptSOAPBodyV1(xmlBodyClean, ephemeralKey);
        System.out.println("############ encryptedSOAPBody: ############");
        System.out.println(encryptedSOAPBody);
        System.out.println("########################");

        // 1.3) - encrypt Ephemeral Key with Redeban certificate Public Key (with RSA-1_5)
        final var redebanPublicKeyPath = "redeban-pubkey.pem";
        final var encryptedEphemeralKey = RedebanUtils.encryptEphemeralKeyV1(ephemeralKey, redebanPublicKeyPath);
        System.out.println("############ encryptedEphemeralKey: ############");
        System.out.println(encryptedEphemeralKey);
        System.out.println("########################");

        // final var ski = RSACryptography.generateSubjectKeyIdentifier(redebanPublicKey);
        final var ski = "MEm79zLpk2XK2hXT3uPyx6VB0Og=";
        System.out.println("############ ski: ############");
        System.out.println(ski);
        System.out.println("########################");

        String xmlOnlyEncryptedBody = RedebanUtils
                .getXmlEnvelopOnlyCiphedBody(encryptedSOAPBody, encryptedEphemeralKey, ski);
        System.out.println("############ xmlOnlyEncryptedBody: ############");
        System.out.println(xmlOnlyEncryptedBody);
        System.out.println("########################");

        /*
         * 2 - assinar o body criptografado acima
         * - usar chave privada da liquido com o RSA com SHA-512
         *
         * */

        /*final var liquidoPrivateKeyPath = "liquido-private.key";
        final var signature = RedebanUtils.signSOAPBodyV1(encryptedSOAPBody, liquidoPrivateKeyPath);
        System.out.println("############ signature: ############");
        System.out.println(signature);
        System.out.println("########################");

        final var xmlEnvelopEncryptedAndSignedBody = getXmlEnvelopCiphedAndSignedBody(
                encryptedSOAPBody, encryptedEphemeralKey, signature
        );*/

        System.out.println("2222222222222222222222222");
        final var xmlSOAPEnvelop = xmlOnlyEncryptedBody;
        // final var xmlSOAPEnvelop = xmlEnvelopEncryptedAndSignedBody;

        // send to the server
        /**
         * URL to our SOAP UI service
         */
        final var SOAP_URI = "https://www.txstestrbm.com:9990/CompraElectronica/Compra";
        URL url = new URL(SOAP_URI);
        URLConnection urlConnection = url.openConnection();

        final var httpsConn = (HttpsURLConnection) urlConnection;

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

        System.out.println("44444444444AAAAAAAAAAAAAAAAAAA");

        OutputStream out = httpsConn.getOutputStream();
        out.write(buffer);
        out.close();

        System.out.println("55555555555555555555555");

        // Read the response and write it to standard out.
        InputStreamReader isr = new InputStreamReader(httpsConn.getInputStream());
        BufferedReader in = new BufferedReader(isr);

        System.out.println("66666666666666666666666");

        String responseString = null;
        String outputString="";
        while ((responseString = in.readLine()) != null)
        {
            outputString = outputString + responseString;
        }

        System.out.println("################# RESPONSE: ###################");
        System.out.println(outputString);
        System.out.println("####################################");

        System.out.println("777777777777777777777777");

        return outputString;
    }

    /*
     * https://www.youtube.com/watch?v=CzHr3CrDFhU
     * https://softwarepulse.co.uk/blog/java-client-calling-soap-web-service/
     * */
    private String executeSOAPRequest1() {

        // *************************************************************************

        HttpURLConnection httpConn = null;
        String responseString = null;
        String outputString="";
        OutputStream out = null;
        InputStreamReader isr = null;
        BufferedReader in = null;

        /*
         * 1 - criptografar o xml do body limpo:
         * - encriptar o body com chave efêmera (gerada pela lib wss4j) com AES_256_CBC (example Hekate RedebanRoute: "KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_256);" )
         * - extrair a chave pública do certificado da redeban e encriptar a chave efêmera com essa chave pública.
         * */

        final var xmlBodyClean = RedebanUtils.getXmlBodyClean();
        // TODO:
        // - gerar chave efêmera;
        // - criptografar o body com a chave efêmera;
        // - criptografar a chave efêmera



        /*
         * 2 - assinar o body criptografado acima
         * - usar chave privada da liquido com o RSA com SHA-512
         *
         * */

        // final var xmlEnvelopCiphedAndSignedBody = getXmlEnvelopCiphedAndSignedBody();

        // 3 - Enviar o request com o certificado

        // Enviar o request
        String xmlInput = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:com=\"http://www.rbm.com.co/esb/comercio/compra/\" xmlns:com1=\"http://www.rbm.com.co/esb/comercio/\" xmlns:esb=\"http://www.rbm.com.co/esb/\">\n" +
                "   <soapenv:Header>\n" +
                "      <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">\n" +
                "         <wsse:UsernameToken>\n" +
                "            <wsse:Username>TestLiquido</wsse:Username>\n" +
                "            <wsse:Password>Liquido.2023</wsse:Password>\n" +
                "         </wsse:UsernameToken>\n" +
                "         <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t<SignedInfo>\n" +
                "\t\t\t\t\t<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/>\n" +
                "\t\t\t\t\t<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512\"/>\n" +
                "\t\t\t\t\t<Reference URI=\"#Timestamp-6a9532da-71c1-4a41-8de1-4ff55b917b7b\">\n" +
                "\t\t\t\t\t\t<Transforms>\n" +
                "\t\t\t\t\t\t\t<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/>\n" +
                "\t\t\t\t\t\t</Transforms>\n" +
                "\t\t\t\t\t\t<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha512\"/>\n" +
                "\t\t\t\t\t\t<DigestValue>D5Uriv4lzx3uV3+BdDpL3T4IuV/2dcA6xcKEoElWNQUNP1cI1kP1ungYWnUYRCWf6O9dw+luhlDrtVTgdVUbeA==</DigestValue>\n" +
                "\t\t\t\t\t</Reference>\n" +
                "\t\t\t\t\t<Reference URI=\"#id-4f5036d7-4c08-45ab-a484-7ce5411d097e\">\n" +
                "\t\t\t\t\t\t<Transforms>\n" +
                "\t\t\t\t\t\t\t<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/>\n" +
                "\t\t\t\t\t\t</Transforms>\n" +
                "\t\t\t\t\t\t<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha512\"/>\n" +
                "\t\t\t\t\t\t<DigestValue>tU5/X7DM40t87hSvq9sB1NmbOqArGE4Z+Wj1h9izaMfwIkDAi2C0kENDu2BUkU5gO5Ceg4ZyYQY5kySzVqFHcQ==</DigestValue>\n" +
                "\t\t\t\t\t</Reference>\n" +
                "\t\t\t\t</SignedInfo>\n" +
                "\t\t\t\t<SignatureValue>igE9bPRWbweqW+iv4amKAGnLZl1+V4pdmubpJfudBBupAZDLO6aMjK9bWEt9ns2K7p7TTmNf9iu7RqpNsvNHQY21eHZHguMj1wvaA+imbUd04OKupBw++dyDV9l0TjY4YCFhYzTRHd8ww4f3C+RmQ4xbnOETB3Q80H+NZSZkQK4Bc+GVfLGPVpdaki0aNw6ftb2EN/Y+PrvSmeqcj01Bk4aYIH7NMHTi6dc3m4ZC+ZLsXo/p+zxfDwK4rXKym377upVLMU4TB6RYIMCKbExVVruCNw+uvV1nnLHB38f2ewMGKE6srzyMpQobjEQUTIIpa7Fv/50cOtVjfWaInHdpAw==</SignatureValue>\n" +
                "\t\t\t\t<KeyInfo>\n" +
                "\t\t\t\t\t<wsse:SecurityTokenReference xmlns=\"\">\n" +
                "\t\t\t\t\t\t<wsse:KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">HZIYNnGSs1YQkdlYPdmf/V4DZO0=</wsse:KeyIdentifier>\n" +
                "\t\t\t\t\t</wsse:SecurityTokenReference>\n" +
                "\t\t\t\t</KeyInfo>\n" +
                "\t\t\t</Signature>\n" +
                "      </wsse:Security>\n" +
                "   </soapenv:Header>\n" +
                "   <soapenv:Body>\n" +
                "      <com:compraProcesarSolicitud>\n" +
                "         <com:cabeceraSolicitud>\n" +
                "            <com:infoPuntoInteraccion>\n" +
                "               <com1:tipoTerminal>WEB</com1:tipoTerminal>\n" +
                "               <com1:idTerminal>SRB00085</com1:idTerminal>\n" +
                "               <com1:idAdquiriente>10203040</com1:idAdquiriente>\n" +
                "               <com1:idTransaccionTerminal>100001</com1:idTransaccionTerminal>\n" +
                "               <com1:modoCapturaPAN>Manual</com1:modoCapturaPAN>\n" +
                "               <com1:capacidadPIN>Virtual</com1:capacidadPIN>\n" +
                "            </com:infoPuntoInteraccion>\n" +
                "         </com:cabeceraSolicitud>\n" +
                "         <com:idPersona>\n" +
                "            <com1:tipoDocumento>CC</com1:tipoDocumento>\n" +
                "            <com1:numDocumento>1000000001</com1:numDocumento>\n" +
                "         </com:idPersona>\t\t\t\t \n" +
                "         <com:infoMedioPago>\t\t\t\t\t\t\t\t\t\t  \n" +
                "            <com:idTarjetaCredito>\n" +
                "               <esb:franquicia>VISA</esb:franquicia>\n" +
                "               <esb:numTarjeta>4005990000001247</esb:numTarjeta>\t\t\t\t\t\t   \n" +
                "               <esb:fechaExpiracion>2025-12-31</esb:fechaExpiracion>\t\t\t\t\t\t\t   \n" +
                "               <esb:codVerificacion>124</esb:codVerificacion>\n" +
                "            </com:idTarjetaCredito>\t\t\t\t\t\t  \t\t\t\t\t\t  \n" +
                "         </com:infoMedioPago>\n" +
                "         <com:infoCompra>\n" +
                "            <com:montoTotal>6</com:montoTotal>\n" +
                "\t\t\t<com:infoImpuestos>\n" +
                "               <com1:tipoImpuesto>IVA</com1:tipoImpuesto>\n" +
                "               <com1:monto>1</com1:monto>\n" +
                "               </com:infoImpuestos>>\t\t\t\t\t\t\t\t\t\t\t\t\t\t\n" +
                "            <com:cantidadCuotas>1</com:cantidadCuotas> \n" +
                "         </com:infoCompra>\n" +
                "\t\t<com:infoPersona>\n" +
                "            <com1:direccion>CALLE 20</com1:direccion>\n" +
                "            <com1:ciudad>BOGOTA</com1:ciudad>\n" +
                "            <com1:departamento>CU</com1:departamento>\n" +
                "            <com1:emailComercio>correo@ejemplo.com</com1:emailComercio>\n" +
                "            <com1:telefonoFijo>8607050</com1:telefonoFijo>\n" +
                "            <com1:celular>30010203040</com1:celular>\n" +
                "         </com:infoPersona>\n" +
                "      </com:compraProcesarSolicitud>\n" +
                "   </soapenv:Body>\n" +
                "</soapenv:Envelope>";

        try {
            System.out.println("11111111111111111111111");

            // String wsURL = "https://www.txstestrbm.com:443/CompraElectronica/Compra";
            URL url = new URL("https://www.txstestrbm.com:9990/CompraElectronica/Compra");

            URLConnection connection = url.openConnection();

            httpConn = (HttpURLConnection) connection;

            System.out.println("22222222222222222222222");

            byte[] buffer = new byte[xmlInput.length()];
            buffer = xmlInput.getBytes();

            System.out.println("33333333333333333333333");

            String SOAPAction = "";
            // Set the appropriate HTTP parameters.
            httpConn.setRequestProperty("Content-Length", String
                    .valueOf(buffer.length));
            httpConn.setRequestProperty("Content-Type",
                    "text/xml; charset=utf-8"); // application/xml
            // x-liquido-service
            // x-liquido-internal-id

            System.out.println("44444444444444444444444");

            httpConn.setRequestProperty("SOAPAction", SOAPAction);
            httpConn.setRequestMethod("POST");
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            out = httpConn.getOutputStream();
            out.write(buffer);
            out.close();

            System.out.println("55555555555555555555555");

            // Read the response and write it to standard out.
            isr = new InputStreamReader(httpConn.getInputStream());
            in = new BufferedReader(isr);

            System.out.println("66666666666666666666666");

            while ((responseString = in.readLine()) != null)
            {
                outputString = outputString + responseString;
            }

            System.out.println("################# RESPONSE: ###################");
            System.out.println(outputString);
            System.out.println("####################################");

            System.out.println("777777777777777777777777");

            return outputString;

            /*
            // Get the response from the web service call
            Document document = parseXmlFile(outputString);
            System.out.println("888888888888888888888888");
            NodeList nodeLst = document.getElementsByTagName("soapenv:Body");
            System.out.println("999999999999999999999999");
            String webServiceResponse = nodeLst.item(0).getTextContent();
            System.out.println("The response from the web service call is : " + webServiceResponse);
            return webServiceResponse;*/
        } catch (Exception e) {
            e.printStackTrace();
            return "Error!";
        }
    }

    private Document parseXmlFile(String in) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            InputSource is = new InputSource(new StringReader(in));
            return db.parse(is);
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (SAXException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String executeSOAPAndHttpsRequestV2() throws Exception {

        final var sc = configureCertificate();

        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        // create an all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };

        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        // ****************************************************
        // 1)
        // 1.1) - generate Ephemeral Key;
        final var ephemeralKey = AESCryptography.generateAESKey();
        System.out.println("############ ephemeralKey: ############");
        System.out.println(Base64.getEncoder().encodeToString(ephemeralKey.getEncoded()));
        System.out.println("########################");

        // IvParameterSpec: Um IV (vetor de inicialização) é necessário para o modo CBC do AES.
        // TODO: Não é necessário enviar ele tbm ????????????????????

        final var iv = AESCryptography.generateIv();
        System.out.println("############ iv: ############");
        System.out.println(Base64.getEncoder().encodeToString(iv.getIV()));
        System.out.println("########################");

        final var xmlBodyCleanStr = RedebanUtils.getXmlBodyClean();

        // 1.2) - encrypt SOAP body clean using Ephemeral Key (with AES-256-CBC);
        final var encryptedSOAPBody = AESCryptography.encrypt(xmlBodyCleanStr, ephemeralKey, iv);
        System.out.println("############ encryptedSOAPBody: ############");
        System.out.println(encryptedSOAPBody);
        System.out.println("########################");

        // 1.3) - encrypt Ephemeral Key with Redeban certificate Public Key (with RSA-1_5)
        final var redebanPublicKeyPath = "redeban-pubkey.pem";
        final var redebanPublicKey = RSACryptography.loadPublicKeyFromPEM(redebanPublicKeyPath);
        final var encryptedEphemeralKey = RSACryptography.encryptAESKeyWithRSA(ephemeralKey, redebanPublicKey);
        System.out.println("############ encryptedEphemeralKey: ############");
        System.out.println(encryptedEphemeralKey);
        System.out.println("########################");



        // TODO: generate the KeyIdentifier ************************* redebanPublicKey ?????????????????????????????????
        //
        final var ski = RSACryptography.generateSKIFromPublicKeyWithSHA1(redebanPublicKey);
        // final var ski = "MEm79zLpk2XK2hXT3uPyx6VB0Og=";
        System.out.println("############ ski: ############");
        System.out.println(ski);
        System.out.println("########################");

        String xmlOnlyEncryptedBody = RedebanUtils
                .getXmlEnvelopOnlyCiphedBody(encryptedSOAPBody, encryptedEphemeralKey, ski);
        System.out.println("############ xmlOnlyEncryptedBody: ############");
        System.out.println(xmlOnlyEncryptedBody);
        System.out.println("########################");

        System.out.println("1111111111111111111111111");


        final var xmlSOAPEnvelop = xmlOnlyEncryptedBody;
        // return sendSOAPRequest(xmlOnlyEncryptedBody);
        // *********************************************
        System.out.println("2222222222222222222222222");
        // final var xmlSOAPEnvelop = xmlEnvelopEncryptedAndSignedBody;

        // send to the server
        /**
         * URL to our SOAP UI service
         */
        final var SOAP_URI = "https://www.txstestrbm.com:9990/CompraElectronica/Compra";
        URL url = new URL(SOAP_URI);
        URLConnection urlConnection = url.openConnection();

        final var httpsConn = (HttpsURLConnection) urlConnection;

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

        System.out.println("44444444444AAAAAAAAAAAAAAAAAAA");

        OutputStream out = httpsConn.getOutputStream();
        out.write(buffer);
        out.close();

        System.out.println("55555555555555555555555");

        // Read the response and write it to standard out.
        InputStreamReader isr = new InputStreamReader(httpsConn.getInputStream());
        BufferedReader in = new BufferedReader(isr);

        System.out.println("66666666666666666666666");

        String responseString = null;
        String outputString="";
        while ((responseString = in.readLine()) != null)
        {
            outputString = outputString + responseString;
        }

        System.out.println("################# RESPONSE: ###################");
        System.out.println(outputString);
        System.out.println("####################################");

        System.out.println("777777777777777777777777");

        return outputString;
    }

    private String sendSOAPRequest(
            final String xmlSOAPEnvelop
    ) throws IOException {

        System.out.println("2222222222222222222222222");
        // final var xmlSOAPEnvelop = xmlEnvelopEncryptedAndSignedBody;

        // send to the server
        /**
         * URL to our SOAP UI service
         */
        final var SOAP_URI = "https://www.txstestrbm.com:9990/CompraElectronica/Compra";
        URL url = new URL(SOAP_URI);
        URLConnection urlConnection = url.openConnection();

        final var httpsConn = (HttpsURLConnection) urlConnection;

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

        System.out.println("44444444444AAAAAAAAAAAAAAAAAAA");

        OutputStream out = httpsConn.getOutputStream();
        out.write(buffer);
        out.close();

        System.out.println("55555555555555555555555");

        // Read the response and write it to standard out.
        InputStreamReader isr = new InputStreamReader(httpsConn.getInputStream());
        BufferedReader in = new BufferedReader(isr);

        System.out.println("66666666666666666666666");

        String responseString = null;
        String outputString="";
        while ((responseString = in.readLine()) != null)
        {
            outputString = outputString + responseString;
        }

        System.out.println("################# RESPONSE: ###################");
        System.out.println(outputString);
        System.out.println("####################################");

        System.out.println("777777777777777777777777");

        return outputString;
    }

    public String executeSOAPAndHttpsRequestV3() throws Exception {

        // Load the Crypto properties
        // Configure the certificate ???????
        final var crypto = Wss4jUtils.loadCrypto(
                CLIENT_KEYSTORE_PASSWORD,
                SERVER_CERTIFICATE_ALIAS,
                CLIENT_KEYSTORE_PATH);


        // TODO: ?????????????????????
        // String bodyCleanStr = RedebanUtils.getXmlBodyClean();
        // final var basicCleanSOAPEnvelop = RedebanUtils.getBasicSOAPEnvelop();
        // final var basicCleanSOAPEnvelop = RedebanUtils.getBasicSOAPEnvelopChinaTeam();

        // final var bodyContent = extractBodyContent(basicCleanSOAPEnvelop);
        // final var bodyContent = RedebanUtils.getBasicCleanSOAPEnvelop();
        final var bodyContent = RedebanUtils.getCleanBodyContent();

        System.out.println("############# bodyContent: ###############");
        System.out.println(bodyContent);
        System.out.println("############################");

        /*if (bodyContent == null) {
            System.out.println("bodyContent is null!");
        }*/

        final var soapXmlDocument = buildSoapXmlDocument(bodyContent);
        final var soapXmlDocumentStr = nodeToString(soapXmlDocument);
        System.out.println("############# soapXmlDocumentStr: ###############");
        System.out.println(soapXmlDocumentStr);
        System.out.println("############################");

        // final var secHeaderStr = "<wsse:Security soap-env:mustUnderstand=\"1\"></wsse:Security>";

        // **********************************
        final var newDoc = Wss4jUtils.initWss4jConfiguration(
                // secHeaderStr,
                soapXmlDocument,
                RedebanUtils.USERNAME,
                RedebanUtils.PASSWORD
        ); // return what?

        System.out.println("############# newDoc: ###############");
        System.out.println(nodeToString(newDoc));
        System.out.println("############################");

        // 1)
        // 1.1) - generate Ephemeral Key;
        // Wss4jUtils.generateEphemeralKey();
        final var ephemeralKey = Wss4jUtils.generateAes256Key();

        return bodyContent;
    }

    private String extractBodyContent(
            final String basicSOAPEnvelop
    ) throws ParserConfigurationException, IOException, SAXException {

        System.out.println("############## extractBodyContent method ################");

        System.out.println("############## basicSOAPEnvelop: ################");
        System.out.println(basicSOAPEnvelop);
        System.out.println("##############################");

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        Document document = factory.newDocumentBuilder().parse(
                new ByteArrayInputStream(basicSOAPEnvelop.getBytes(StandardCharsets.UTF_8)));

        System.out.println("############## document: ################");
        System.out.println(nodeToString(document));
        System.out.println("##############################");

        // Get body element
        String bodyContent = null;
        // NodeList bodyList = document.getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/", "Body"); // *************************
        // NodeList bodyList = document.getElementsByTagName("Body");
        // NodeList bodyList = document.getChildNodes();

        NodeList bodyList = document.getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/", "Body");
        System.out.println("############## bodyList.getLength(): ################");
        System.out.println(bodyList.getLength());
        System.out.println("##############################");

        Node bodyNode = bodyList.item(0);
        System.out.println("############## bodyNode: ################");
        System.out.println(nodeToString(bodyNode));
        System.out.println("##############################");

        /*NodeList bodyChildList = document.getElementsByTagNameNS("http://www.rbm.com.co/esb/comercio/compra/", "ns0:compraProcesarSolicitud");
        System.out.println("############## bodyChildList.getLength(): ################");
        System.out.println(bodyChildList.getLength());
        System.out.println("##############################");*/


        /*System.out.println("############## bodyList.item(0): ################");
        System.out.println(nodeToString(bodyElement));
        System.out.println("##############################");*/

        if (bodyList.getLength() > 0) {
            System.out.println("1111111111111111111111111");
            // Element bodyElement = (Element) bodyList.item(0);

            // we can use bodyNode.appendChild();

            NodeList bodyNodeList =bodyNode.getChildNodes();

            System.out.println("############## bodyNodeList.getLength(): ################");
            System.out.println(bodyNodeList.getLength());
            System.out.println("##############################");

            // Get body content
            bodyContent = nodeToString(bodyNode.getFirstChild());
            // bodyContent = nodeToString(bodyElement.getFirstChild());
            System.out.println("Extracted Body Content:" + bodyContent);
        } else {
            System.out.println("***** ERROR - No Body element found.");
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
            System.out.println(" Redeban convert node to String error: " + e.getMessage());
            return null;
        }
    }

    private Document buildSoapXmlDocument(final String bodyContent) throws Exception {
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
        /*Document doc = soapMessageToDocument(soapMessage);
        return doc;*/
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
}
