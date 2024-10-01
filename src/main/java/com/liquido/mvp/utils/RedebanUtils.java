package com.liquido.mvp.utils;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
// import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

public class RedebanUtils {

    public static final String USERNAME = "TestLiquido";
    public static final String PASSWORD = "Liquido.2023";

    // private static final String key = "aesEncryptionKey";
    // private static final String initVector = "encryptionIntVec"; // ??????????????????????

    public static String getXmlBodyClean() {
        return "<soapenv:Body>\n" +
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
                "\t\t         <com:idPersona>\n" +
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
                "               </com:infoImpuestos>\t\t\t\t\t\t\t\t\t\t\t\t\t\t\n" +
                "            <com:cantidadCuotas>1</com:cantidadCuotas> \n" +
                "         </com:infoCompra>\n" +
                "\t\t<com:infoPersona>\n" +
                "            <com1:direccion>CALLE 20</com1:direccion>\n" +
                "            <com1:ciudad>BOGOTA</com1:ciudad>\n" +
                "            <com1:departamento>CU</com1:departamento>\n" +
                "            <com1:emailComercio>correo@ejemplo.com</com1:emailComercio>\n" +
                "            <com1:telefonoFijo>8607050</com1:telefonoFijo>\n" +
                "            <com1:celular>30010203040</com1:celular>\n" +
                "         </com:infoPersona>\t\t\t\t\t\t\t\t \n" +
                "      </com:compraProcesarSolicitud>\n" +
                "</soapenv:Body>";
    }

    public static String getXmlEnvelopOnlyCiphedBody(
            final String cipherBodyValue,
            final String cipherEphemeralKeyValue,
            final String ski
    ) {
        /*
        * <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
					<wsse:SecurityTokenReference>
						<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">MEm79zLpk2XK2hXT3uPyx6VB0Og=</wsse:KeyIdentifier>
					</wsse:SecurityTokenReference>
				</dsig:KeyInfo>
        * TODO: KeyIdentifier ????????????????
        * */
        return String.format("\"<soap-env:Envelope xmlns:wsse=\\\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\\\" xmlns:soap-env=\\\"http://schemas.xmlsoap.org/soap/envelope/\\\">\\n\" +\n" +
                        "                \"\\t<soap-env:Header>\\n\" +\n" +
                        "                \"\\t\\t<wsse:Security soap-env:mustUnderstand=\\\"1\\\">\\n\" +\n" +
                        "                \"\\t\\t\\t<xenc:EncryptedKey xmlns:xenc=\\\"http://www.w3.org/2001/04/xmlenc#\\\">\\n\" +\n" +
                        "                \"\\t\\t\\t\\t<xenc:EncryptionMethod xmlns:dsig=\\\"http://www.w3.org/2000/09/xmldsig#\\\" Algorithm=\\\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\\\"/>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t<dsig:KeyInfo xmlns:dsig=\\\"http://www.w3.org/2000/09/xmldsig#\\\">\\n\" +\n" +
                        "                \"\\t\\t\\t\\t\\t<wsse:SecurityTokenReference>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t\\t\\t<wsse:KeyIdentifier ValueType=\\\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\\\" EncodingType=\\\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\\\">MEm79zLpk2XK2hXT3uPyx6VB0Og=</wsse:KeyIdentifier>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t\\t</wsse:SecurityTokenReference>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t</dsig:KeyInfo>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t<xenc:CipherData xmlns:dsig=\\\"http://www.w3.org/2000/09/xmldsig#\\\">\\n\" +\n" +
                        "                \"\\t\\t\\t\\t\\t<xenc:CipherValue>%s</xenc:CipherValue>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t</xenc:CipherData>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t<xenc:ReferenceList>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t\\t<xenc:DataReference URI=\\\"#body\\\"/>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t</xenc:ReferenceList>\\n\" +\n" +
                        "                \"\\t\\t\\t</xenc:EncryptedKey>\\n\" +\n" +
                        "                \"\\t\\t\\t<wsse:UsernameToken>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t<wsse:Username>%s</wsse:Username>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t<wsse:Password>%s</wsse:Password>\\n\" +\n" +
                        "                \"\\t\\t\\t</wsse:UsernameToken>\\n\" +\n" +
                        "                \"\\t\\t</wsse:Security>\\n\" +\n" +
                        "                \"\\t</soap-env:Header>\\n\" +\n" +
                        "                \"\\t<soap-env:Body xmlns:ns15=\\\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\\\" ns15:Id=\\\"id-4f5036d7-4c08-45ab-a484-7ce5411d097e\\\">\\n\" +\n" +
                        "                \"\\t\\t<xenc:EncryptedData xmlns:xenc=\\\"http://www.w3.org/2001/04/xmlenc#\\\" Id=\\\"body\\\" Type=\\\"http://www.w3.org/2001/04/xmlenc#Content\\\">\\n\" +\n" +
                        "                \"\\t\\t\\t<xenc:EncryptionMethod Algorithm=\\\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\\\"/>\\n\" +\n" +
                        "                \"\\t\\t\\t<xenc:CipherData>\\n\" +\n" +
                        "                \"\\t\\t\\t\\t<xenc:CipherValue>%s</xenc:CipherValue>\\n\" +\n" +
                        "                \"\\t\\t\\t</xenc:CipherData>\\n\" +\n" +
                        "                \"\\t\\t</xenc:EncryptedData>\\n\" +\n" +
                        "                \"\\t</soap-env:Body>\\n\" +\n" +
                        "                \"</soap-env:Envelope>\"",
                // ski,
                cipherEphemeralKeyValue,
                USERNAME,
                PASSWORD,
                cipherBodyValue);
    }

    private String getXmlEnvelopCiphedAndSignedBody(
            final String cipherBodyValue,
            final String cipherEphemeralKeyValue,
            final String signature
    ) {
        return String.format("<soap-env:Envelope xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:soap-env=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                        "\t<soap-env:Header>\n" +
                        "\t\t<wsse:Security soap-env:mustUnderstand=\"1\">\n" +
                        "\t\t\t<xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\n" +
                        "\t\t\t\t<xenc:EncryptionMethod xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\" Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/>\n" +
                        "\t\t\t\t<dsig:KeyInfo xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                        "\t\t\t\t\t<wsse:SecurityTokenReference>\n" +
                        "\t\t\t\t\t\t<wsse:KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">MEm79zLpk2XK2hXT3uPyx6VB0Og=</wsse:KeyIdentifier>\n" +
                        "\t\t\t\t\t</wsse:SecurityTokenReference>\n" +
                        "\t\t\t\t</dsig:KeyInfo>\n" +
                        "\t\t\t\t<xenc:CipherData xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                        "\t\t\t\t\t<xenc:CipherValue>%s</xenc:CipherValue>\n" +
                        "\t\t\t\t</xenc:CipherData>\n" +
                        "\t\t\t\t<xenc:ReferenceList>\n" +
                        "\t\t\t\t\t<xenc:DataReference URI=\"#body\"/>\n" +
                        "\t\t\t\t</xenc:ReferenceList>\n" +
                        "\t\t\t</xenc:EncryptedKey>\n" +
                        "\t\t\t<wsse:UsernameToken>\n" +
                        "\t\t\t\t<wsse:Username>%s</wsse:Username>\n" +
                        "\t\t\t\t<wsse:Password>%s</wsse:Password>\n" +
                        "\t\t\t</wsse:UsernameToken>\n" +
                        "\t\t\t<wsu:Timestamp xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"Timestamp-0d55fa6a-7603-4689-b8f5-4ff55b91a725\">\n" +
                        "\t\t\t\t<wsu:Created>2024-03-21T13:51:38Z</wsu:Created>\n" +
                        "\t\t\t\t<wsu:Expires>2024-03-21T13:56:38Z</wsu:Expires>\n" +
                        "\t\t\t</wsu:Timestamp>\n" +
                        "\t\t\t<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                        "\t\t\t\t<SignedInfo>\n" +
                        "\t\t\t\t\t<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/>\n" +
                        "\t\t\t\t\t<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512\"/>\n" +
                        "\t\t\t\t\t<Reference URI=\"#Timestamp-0d55fa6a-7603-4689-b8f5-4ff55b91a725\">\n" +
                        "\t\t\t\t\t\t<Transforms>\n" +
                        "\t\t\t\t\t\t\t<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/>\n" +
                        "\t\t\t\t\t\t</Transforms>\n" +
                        "\t\t\t\t\t\t<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha512\"/>\n" +
                        "\t\t\t\t\t\t<DigestValue>Qxrs556EEALebb6AE39cUonkMgoGkOvCEFpRI2kDPKlefJnVY7cjQsw604PAoT00IDbK3tLKimeJ4NmCHHOQFA==</DigestValue>\n" +
                        "\t\t\t\t\t</Reference>\n" +
                        "\t\t\t\t\t<Reference URI=\"#id-4f5036d7-4c08-45ab-a484-7ce5411d097e\">\n" +
                        "\t\t\t\t\t\t<Transforms>\n" +
                        "\t\t\t\t\t\t\t<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/>\n" +
                        "\t\t\t\t\t\t</Transforms>\n" +
                        "\t\t\t\t\t\t<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha512\"/>\n" +
                        "\t\t\t\t\t\t<DigestValue>uDDn7WZPTbUnOMfY69AKri7mcZk4jS1nDuzSmqeETnhtK9gBMdIEEAtoii920i7lMXoKqqRfmX35u0VoUMi9HA==</DigestValue>\n" +
                        "\t\t\t\t\t</Reference>\n" +
                        "\t\t\t\t</SignedInfo>\n" +
                        "\t\t\t\t<SignatureValue>%s</SignatureValue>\n" +
                        "\t\t\t\t<KeyInfo>\n" +
                        "\t\t\t\t\t<wsse:SecurityTokenReference xmlns=\"\">\n" +
                        "\t\t\t\t\t\t<wsse:KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">HZIYNnGSs1YQkdlYPdmf/V4DZO0=</wsse:KeyIdentifier>\n" +
                        "\t\t\t\t\t</wsse:SecurityTokenReference>\n" +
                        "\t\t\t\t</KeyInfo>\n" +
                        "\t\t\t</Signature>\n" +
                        "\t\t</wsse:Security>\n" +
                        "\t</soap-env:Header>\n" +
                        "\t<soap-env:Body xmlns:ns15=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" ns15:Id=\"id-4f5036d7-4c08-45ab-a484-7ce5411d097e\">\n" +
                        "\t\t<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"body\" Type=\"http://www.w3.org/2001/04/xmlenc#Content\">\n" +
                        "\t\t\t<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/>\n" +
                        "\t\t\t<xenc:CipherData>\n" +
                        "\t\t\t\t<xenc:CipherValue>%s</xenc:CipherValue>\n" +
                        "\t\t\t</xenc:CipherData>\n" +
                        "\t\t</xenc:EncryptedData>\n" +
                        "\t</soap-env:Body>\n" +
                        "</soap-env:Envelope>",
                cipherEphemeralKeyValue,
                USERNAME,
                PASSWORD,
                signature,
                cipherBodyValue);
    }

    public static String encryptSOAPBodyV1(String bodyClean, String ephemeralKey) {
        try {
            // IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            // SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            SecretKeySpec skeySpec = new SecretKeySpec(ephemeralKey.getBytes("UTF-8"), "AES");

            // "RSA-OAEP-MGF1 with AES-256-CBC" or 3DES-CBC with RSA-1_5 (RSA PKCS #1 v1.5)
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING"); // xml -> EncryptionMethod = aes256-cbc
            // cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

            byte[] encrypted = cipher.doFinal(bodyClean.getBytes());
            return Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String encryptEphemeralKeyV1(String ephemeralKey, String publicKeyPath) {
        FileInputStream is = null;

        try {
            is = new FileInputStream(new File(publicKeyPath));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }

        try {
            String publicKeyContent = new String(is.readAllBytes());

            publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");

            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(java.util.Base64.getDecoder().decode(publicKeyContent));
            RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // EncryptionMethod = rsa-1_5
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encrypted = cipher.doFinal(ephemeralKey.getBytes());
            return Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String signSOAPBodyV1(String ecryptedSOAPBody, String privateKeyPath) {
        File file = null;
        FileInputStream is = null;

        try {
            file = new File(privateKeyPath);
            is = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }

        /*final byte[] privKeyBytes;
        try {
            privKeyBytes = is.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }*/

        String privateKeyContent = null;
        try {
            privateKeyContent = new String(is.readAllBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");

        return generateSHA512Signature(ecryptedSOAPBody, privateKeyContent);
        // generateSHA256Hash(privateKeyContent);

        /*Signature privateSignature = null;
        try {
            privateSignature = Signature.getInstance("SHA512withRSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }*/

        // PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(privateKeyContent));
        // PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

        // X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(java.util.Base64.getDecoder().decode(privateKeyContent));

        /*byte[] privKeyBytes = new byte[(int) file.length()];
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(privateKeyContent)); */

        /*DataInputStream dis = new DataInputStream(is);

        byte[] keyBytes = new byte[(int) file.length()];
        try {
            dis.readFully(keyBytes);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            dis.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        RSAPrivateKey privateKey = null;
        try {
            privateKey = (RSAPrivateKey) kf.generatePrivate(spec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        try {
            privateSignature.initSign(privateKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        try {
            privateSignature.update(ecryptedSOAPBody.getBytes(StandardCharsets.UTF_8));
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }

        byte[] signature = null;
        try {
            signature = privateSignature.sign();
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }

        return bytesToHex(signature);*/
    }

    private static String generateSHA512Signature(final String input, final String key) {
        String result = "";

        try {
            final String HMAC_SHA512 = "HmacSHA512";
            final byte[] byteKey = key.getBytes(StandardCharsets.UTF_8);
            Mac sha512Hmac = Mac.getInstance(HMAC_SHA512);
            SecretKeySpec keySpec = new SecretKeySpec(byteKey, HMAC_SHA512);
            sha512Hmac.init(keySpec);
            byte[] macData = sha512Hmac.doFinal(input.getBytes(StandardCharsets.UTF_8));

            // Can either base64 encode or put it right into hex
            result = java.util.Base64.getEncoder().encodeToString(macData);
            // result = bytesToHex(macData);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        } finally {
            // Put any cleanup here
            System.out.println("Done");
            return result;
        }
    }

    /*private String generateSHA256Hash(String input) {
        try {
            // Create a MessageDigest instance for SHA-512
            MessageDigest digest = MessageDigest.getInstance("SHA-512"); // SHA512withRSA

            // Perform the hash computation
            byte[] encodedhash = digest.digest(input.getBytes());

            // Convert byte array into a hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte b : encodedhash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }*/

    private static String bytesToHex(byte[] encodedhash) {
        // Convert byte array into a hexadecimal string
        StringBuilder hexString = new StringBuilder();
        for (byte b : encodedhash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /*private static String bytesToHex(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }*/

}
