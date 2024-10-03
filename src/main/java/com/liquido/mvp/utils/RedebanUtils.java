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

    public static final String VENDOR_PUBLIC_KEY_CONTENT = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxf5q+f14jE7E6m63sDSS\n" +
            "CAIDzYmeYw0Cj8lxFeRfPSSaXO40A+s+iLYMTfcuoOjIFPAsOzIJq1p1cRam7bDV\n" +
            "g6Vdf8fVZic0kxZr9g3N6afSUfVDJStNeFWiXPWZifMdvREo0tpQWJpc6IVhBdhO\n" +
            "HB270XP9Iq6qSOOi3HwluvbrcAumVimBqPgVaJyQ2VOlX8mEtCuYmi/9+quP4/Sw\n" +
            "po4UcRZvfsqtzSS8959mlpCpYQoitxmlsHHI8y+3bdhhCDi2ea9gHp09WxDNyaWs\n" +
            "lAPzYuENN1B9dw1tPP4UefessrY2cShiBAKLYG+5czSwVT/R0ynB+ualtZq0mY4t\n" +
            "arooFizEi69S7HANu4I1ywO2PPR8qBMTO2pf9hXqW7Sep5S3D00EpUwl2tBWUKGb\n" +
            "JiEhrCkmuMxprcQjQ/tOgS8N4EtVMTEpC2d4+Ez3AHEOvv/ye0WGkv3nabLRG5mu\n" +
            "BLSfhTicSnG92Mf3Cqp2dcouAY/gEGqbdxMUDf61kyfzfAsLjEBcM5oKHV8Tb3xu\n" +
            "zvV0WvjbV1a1UHLQAsq20PCavjTFhOhG40X6tx4HYQBHRURlvgVMB1GVTp3OPO9L\n" +
            "sjOhr/CE69xEq5+ni3xVG4rzDeB1MIkLJ6loydJvhGzrlMSIJOBUgLIo66qAYVSV\n" +
            "p/Bp7IozD4nrajsj+jCj8pkCAwEAAQ==";

    public static final String USERNAME = "TestLiquido";
    public static final String PASSWORD = "Liquido.2023";

    public static final String LQD_PUBLIC_KEY_CONTENT = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUQyVENDQXNFQ0ZDV2hFZjQ5YlNtbHB2dUJvemNqTDdIZ0pUUUNNQTBHQ1NxR1NJYjNEUUVCRFFVQU1JR28KTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tRMkZzYVdadmNtNXBZVEVXTUJRR0ExVUVCd3dOVFc5MQpiblJoYVc0Z1ZtbGxkekVRTUE0R0ExVUVDZ3dIVEdseGRXbGtiekVVTUJJR0ExVUVDd3dMUlc1bmFXNWxaWEpwCmJtY3hJREFlQmdOVkJBTU1GMHhwY1hWcFpHOHRjR0Y1YldWdWRDMTBaWE4wYVc1bk1TSXdJQVlKS29aSWh2Y04KQVFrQkZoTnpkWEJ3YjNKMFFHeHBjWFZwWkc4dVkyOXRNQjRYRFRJME1EUXlOREE0TlRBeU4xb1hEVEkxTURReQpOREE0TlRBeU4xb3dnYWd4Q3pBSkJnTlZCQVlUQWxWVE1STXdFUVlEVlFRSURBcERZV3hwWm05eWJtbGhNUll3CkZBWURWUVFIREExTmIzVnVkR0ZwYmlCV2FXVjNNUkF3RGdZRFZRUUtEQWRNYVhGMWFXUnZNUlF3RWdZRFZRUUwKREF0RmJtZHBibVZsY21sdVp6RWdNQjRHQTFVRUF3d1hUR2x4ZFdsa2J5MXdZWGx0Wlc1MExYUmxjM1JwYm1jeApJakFnQmdrcWhraUc5dzBCQ1FFV0UzTjFjSEJ2Y25SQWJHbHhkV2xrYnk1amIyMHdnZ0VpTUEwR0NTcUdTSWIzCkRRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRGcrMGlpSFV3Q0p2VzFxVFplRXhMeHAvcTNYTFl4VkUvYmtqZUkKZ1c3ekp5eWFOL3k0bzlKajBycG5xUnVRclpWejdHRngwejN5L2VvNmhNWjhnaDI3clY5Y0ErZUpiaXhmOFI1Vgp5dTZLNFVpSXhjSFVyWVNQSy94dW1MeXRnaXY0TW84ZnhMV0liR3J6QUVPUFVBWndIaDdFdStkek5zV1gvQWJwCmJOTFd6QTV0MmRpYUlhUEQ4N1RVRW5GcDZBSDFsK1h5NFBseWpwbzB0cC9KMUlndmYybkZrS2VLM0RYTjJFWXEKS25ZWndBOUNBNGRPLzArNCtZbERmYmtLSnhrWUl0OW5sYjRCb3huR25SbEx6UFBHQVM4Y1dwaHJkVWJQcHd0ZQplZkNXZmFlbTc0U2tVeG5LQW13OWJ6Rk04K3BSTDh2T1BiTzhDMFZrcFhid3lINWpBZ01CQUFFd0RRWUpLb1pJCmh2Y05BUUVOQlFBRGdnRUJBSk1hMTFoV3BvTjN2dlFiQWpCY0cyM2ZKRzZPRFhlUHJIRGNPQnhsNlJtdXRYc0UKWW1mZWlHQ2lqd2pJbm1nWGt1aVpXU3BydmErelBjUkxienFHSTErWWRHZWMwSTNKbGpUZFFYRXkvbnU2NmVtWAp4QjQ2YVVlcWd1UEFjTUg3U2k1cVpKbWxqU0x0aFlNU2hSOUJVZVNxKzRJLzlOWWpBeEdCMmlUVXI5VURDZHNXClA3R1BYU2xNUi9aYjBhS0hBbjV0dmhvVG1nNVF5Z0NsK2ZHY080RXRlNitiSEJoZU9oZ0N4R2kxZU9FQkFZbkMKVFI0OXF6T2VHdjlkY01PL0cxa3ExMGE1OW5sd255TVNiMjQyZEo4YTVnTXFReG81M05PT1lTWjFROE9Ddm4rLwppMGdsSXo4VzZLbkhSMHRwYURWYlQrazZaY0FGaTNuRWdhRGJXWDA9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K";
    public static final String LQD_PRIVATE_KEY_CONTENT = "MIIEpQIBAAKCAQEA4PtIoh1MAib1tak2XhMS8af6t1y2MVRP25I3iIFu8ycsmjf8\n" +
            "uKPSY9K6Z6kbkK2Vc+xhcdM98v3qOoTGfIIdu61fXAPniW4sX/EeVcruiuFIiMXB\n" +
            "1K2Ejyv8bpi8rYIr+DKPH8S1iGxq8wBDj1AGcB4exLvnczbFl/wG6WzS1swObdnY\n" +
            "miGjw/O01BJxaegB9Zfl8uD5co6aNLafydSIL39pxZCnitw1zdhGKip2GcAPQgOH\n" +
            "Tv9PuPmJQ325CicZGCLfZ5W+AaMZxp0ZS8zzxgEvHFqYa3VGz6cLXnnwln2npu+E\n" +
            "pFMZygJsPW8xTPPqUS/Lzj2zvAtFZKV28Mh+YwIDAQABAoIBAQDVARPjaJlt8DTx\n" +
            "qSMwLh7hbIiS0dQtIAX7fJPXSbQhwhUYbal3pqKqn/ib7B+M+stk1YfsnHMqe/wn\n" +
            "K05A03ATIDIIjCnKk+SvcTmnQFpYYrKpy5GYKjA23Q5CJ5l7LKM0eanIChVU9FDN\n" +
            "gJJ2PO3beKjo2n5nNpQdMR/aII39ja34/ygvBzAGGxR1eUguq1TBggerdmhlIRuG\n" +
            "v8t7LMx2901fN5nUdgSBy55OT5e8I66JgXu60Lzl563Fnb50tDNcvXaItdINaRgc\n" +
            "rgAltymPgzkFJg4lWEE5+PRNxDao4U9JPaxY79hZAYbt1bmDeaKbzoLNsJmf60aw\n" +
            "hrEy6YQBAoGBAPc6EDXvcxG8slKp7MsmGFTczZJoZlzm9iEytueY0+zpWsEnjWrs\n" +
            "+nLNe+vfczB9fPyVgTdLqZigCK+4CQP/hM0mpKTyfaTZdCS/eTQzODOlaOPFGFIt\n" +
            "Rohwh62VvRzKPJRneTaYkaO+ZD8bp8oL1W6CY/qv2cn7/4hp/KOaE5rTAoGBAOj3\n" +
            "Ihao5vMlLf946Q8PtlAY1A72nemq2MRc2kfbexiNSkS2SPnC6oEnX8j0k7tUdVTD\n" +
            "z8pqyttxgw3nkCbnkeRdSiFYyhePLzLK6SfzyAvAS2tjioukWE4S1cS8wQivxQCW\n" +
            "rarEehhm36lwFao4U4iGo43ux9PD/IchJ/XS9zQxAoGBAPBCY0KnQ8K3CO3A6bi7\n" +
            "euXt93ITN3eNlSDKMmp8YWhZl7MjBxIk33f2LjoaW82CBpdJi9v7EgSbchWi2lAi\n" +
            "YCMnLNaIOoacNX0I/3c1V6cJVxgTkQE7stIh2hld7f0upRTsQiZGuzLQcofKDpQS\n" +
            "UAcnfJZBk3vyBHHD3pv3vpm1AoGAKX2aPJ7oQvWkM5O9LkmGFs3VNrUFetBKuu4u\n" +
            "kg2s5rqDN6mfZZwpV8dDb+7fQMXR/77ACzTp3BtjU96h9cvYV+ulgDroAzolFc69\n" +
            "p7frMOyWghHAYw5qC72fBOL5Hirv0yMC2x8S/7WSsAKeWSqe9fnEt0qHnFeTah2l\n" +
            "mEpybIECgYEAsHyAwFxQxkyQVgBWFucJdKvib0CYSukhCGmgc5Qp8hap7JHjTK+2\n" +
            "B+W9CWi9Tcb5xfMfe5DH3cIy2UB3qmhHmE8NXV6pLnfvC9OLPeF0PsoD7zaYvHkt\n" +
            "JPDscGzYF6dA5vONBCQZouwtQgkBU/I5cA76aQM+xaX1sI1fWMANlsA=";

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
                        "                \"\\t\\t\\t\\t\\t\\t<wsse:KeyIdentifier ValueType=\\\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\\\" EncodingType=\\\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\\\">%s</wsse:KeyIdentifier>\\n\" +\n" +
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
                ski,
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

    public static String getBasicCleanSOAPEnvelop() {
        return "<Envelope\n" +
                "\txmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"\n" +
                "\txmlns:soap-env=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<Body ns15:Id=\"id-4f5036d7-4c08-45ab-a484-7ce5411d097e\"\n" +
                "\t\txmlns:ns15=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\n" +
                "\t\t<ns0:compraProcesarSolicitud\n" +
                "\t\t\txmlns:ns0=\"http://www.rbm.com.co/esb/comercio/compra/\">\n" +
                "\t\t\t<ns0:cabeceraSolicitud>\n" +
                "\t\t\t\t<ns0:infoPuntoInteraccion>\n" +
                "\t\t\t\t\t<ns1:tipoTerminal\n" +
                "\t\t\t\t\t\txmlns:ns1=\"http://www.rbm.com.co/esb/comercio/\">POS\n" +
                "\t\t\t\t\t</ns1:tipoTerminal>\n" +
                "\t\t\t\t\t<ns2:idTerminal\n" +
                "\t\t\t\t\t\txmlns:ns2=\"http://www.rbm.com.co/esb/comercio/\">SRB01589\n" +
                "\t\t\t\t\t</ns2:idTerminal>\n" +
                "\t\t\t\t\t<ns3:idAdquiriente\n" +
                "\t\t\t\t\t\txmlns:ns3=\"http://www.rbm.com.co/esb/comercio/\">20304102\n" +
                "\t\t\t\t\t</ns3:idAdquiriente>\n" +
                "\t\t\t\t\t<ns4:idTransaccionTerminal\n" +
                "\t\t\t\t\t\txmlns:ns4=\"http://www.rbm.com.co/esb/comercio/\">326945\n" +
                "\t\t\t\t\t</ns4:idTransaccionTerminal>\n" +
                "\t\t\t\t\t<ns5:modoCapturaPAN\n" +
                "\t\t\t\t\t\txmlns:ns5=\"http://www.rbm.com.co/esb/comercio/\">Banda\n" +
                "\t\t\t\t\t</ns5:modoCapturaPAN>\n" +
                "\t\t\t\t\t<ns6:capacidadPIN\n" +
                "\t\t\t\t\t\txmlns:ns6=\"http://www.rbm.com.co/esb/comercio/\">Permitido\n" +
                "\t\t\t\t\t</ns6:capacidadPIN>\n" +
                "\t\t\t\t</ns0:infoPuntoInteraccion>\n" +
                "\t\t\t</ns0:cabeceraSolicitud>\n" +
                "\t\t\t<ns0:infoMedioPago>\n" +
                "\t\t\t\t<ns0:idTrack>\n" +
                "\t\t\t\t\t<ns7:Franquicia\n" +
                "\t\t\t\t\t\txmlns:ns7=\"http://www.rbm.com.co/esb/\">MasterCard\n" +
                "\t\t\t\t\t</ns7:Franquicia>\n" +
                "\t\t\t\t\t<ns8:track\n" +
                "\t\t\t\t\t\txmlns:ns8=\"http://www.rbm.com.co/esb/\">2223590400108111=25121011111199911111\n" +
                "\t\t\t\t\t</ns8:track>\n" +
                "\t\t\t\t\t<ns9:tipoCuenta\n" +
                "\t\t\t\t\t\txmlns:ns9=\"http://www.rbm.com.co/esb/\">Credito\n" +
                "\t\t\t\t\t</ns9:tipoCuenta>\n" +
                "\t\t\t\t</ns0:idTrack>\n" +
                "\t\t\t\t<ns0:infoAutenticacion>\n" +
                "\t\t\t\t\t<ns10:clave\n" +
                "\t\t\t\t\t\txmlns:ns10=\"http://www.rbm.com.co/esb/\">26B03DA72C4B5F35\n" +
                "\t\t\t\t\t</ns10:clave>\n" +
                "\t\t\t\t\t<ns11:formatoClave\n" +
                "\t\t\t\t\t\txmlns:ns11=\"http://www.rbm.com.co/esb/\">3DES\n" +
                "\t\t\t\t\t</ns11:formatoClave>\n" +
                "\t\t\t\t</ns0:infoAutenticacion>\n" +
                "\t\t\t</ns0:infoMedioPago>\n" +
                "\t\t\t<ns0:infoCompra>\n" +
                "\t\t\t\t<ns0:montoTotal>5000</ns0:montoTotal>\n" +
                "\t\t\t\t<ns0:referencia>CPNJDQMEW4LV</ns0:referencia>\n" +
                "\t\t\t\t<ns0:cantidadCuotas>2</ns0:cantidadCuotas>\n" +
                "\t\t\t\t<ns0:infoFacilitador>\n" +
                "\t\t\t\t\t<ns12:marcTerminal\n" +
                "\t\t\t\t\t\txmlns:ns12=\"http://www.rbm.com.co/esb/\">BOLD*Stg Juan\n" +
                "\t\t\t\t\t</ns12:marcTerminal>\n" +
                "\t\t\t\t\t<ns13:FacilitadorID\n" +
                "\t\t\t\t\t\txmlns:ns13=\"http://www.rbm.com.co/esb/\">260278\n" +
                "\t\t\t\t\t</ns13:FacilitadorID>\n" +
                "\t\t\t\t\t<ns14:SubMerchID\n" +
                "\t\t\t\t\t\txmlns:ns14=\"http://www.rbm.com.co/esb/\">NDH86D9U04\n" +
                "\t\t\t\t\t</ns14:SubMerchID>\n" +
                "\t\t\t\t</ns0:infoFacilitador>\n" +
                "\t\t\t</ns0:infoCompra>\n" +
                "\t\t</ns0:compraProcesarSolicitud>\n" +
                "\t</Body>\n" +
                "</Envelope>";
    }

    public static String getBasicSOAPEnvelop() {
        return "<Envelope\n" +
                "\txmlns=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<Body\n" +
                "\t\txmlns:wstxns1=\"http://schemas.xmlsoap.org/soap/envelope/\" wstxns1:type=\"purchase\">\n" +
                "\t\t<ns0:compraProcesarSolicitud\n" +
                "\t\t\txmlns:ns0=\"http://www.rbm.com.co/esb/comercio/compra/\">\n" +
                "\t\t\t<ns0:cabeceraSolicitud>\n" +
                "\t\t\t\t<ns0:infoPuntoInteraccion>\n" +
                "\t\t\t\t\t<ns1:tipoTerminal\n" +
                "\t\t\t\t\t\txmlns:ns1=\"http://www.rbm.com.co/esb/comercio/\">POS\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns1:tipoTerminal>\n" +
                "\t\t\t\t\t<ns2:idTerminal\n" +
                "\t\t\t\t\t\txmlns:ns2=\"http://www.rbm.com.co/esb/comercio/\">SRB01589\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns2:idTerminal>\n" +
                "\t\t\t\t\t<ns3:idAdquiriente\n" +
                "\t\t\t\t\t\txmlns:ns3=\"http://www.rbm.com.co/esb/comercio/\">20304102\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns3:idAdquiriente>\n" +
                "\t\t\t\t\t<ns4:idTransaccionTerminal\n" +
                "\t\t\t\t\t\txmlns:ns4=\"http://www.rbm.com.co/esb/comercio/\">326945\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns4:idTransaccionTerminal>\n" +
                "\t\t\t\t\t<ns5:modoCapturaPAN\n" +
                "\t\t\t\t\t\txmlns:ns5=\"http://www.rbm.com.co/esb/comercio/\">Banda\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns5:modoCapturaPAN>\n" +
                "\t\t\t\t\t<ns6:capacidadPIN\n" +
                "\t\t\t\t\t\txmlns:ns6=\"http://www.rbm.com.co/esb/comercio/\">Permitido\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns6:capacidadPIN>\n" +
                "\t\t\t\t</ns0:infoPuntoInteraccion>\n" +
                "\t\t\t</ns0:cabeceraSolicitud>\n" +
                "\t\t\t<ns0:infoMedioPago>\n" +
                "\t\t\t\t<ns0:idTrack>\n" +
                "\t\t\t\t\t<ns7:Franquicia\n" +
                "\t\t\t\t\t\txmlns:ns7=\"http://www.rbm.com.co/esb/\">MasterCard\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns7:Franquicia>\n" +
                "\t\t\t\t\t<ns8:track\n" +
                "\t\t\t\t\t\txmlns:ns8=\"http://www.rbm.com.co/esb/\">2223590400108111=25121011111199911111\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns8:track>\n" +
                "\t\t\t\t\t<ns9:tipoCuenta\n" +
                "\t\t\t\t\t\txmlns:ns9=\"http://www.rbm.com.co/esb/\">Credito\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns9:tipoCuenta>\n" +
                "\t\t\t\t</ns0:idTrack>\n" +
                "\t\t\t\t<ns0:infoAutenticacion>\n" +
                "\t\t\t\t\t<ns10:clave\n" +
                "\t\t\t\t\t\txmlns:ns10=\"http://www.rbm.com.co/esb/\">26B03DA72C4B5F35\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns10:clave>\n" +
                "\t\t\t\t\t<ns11:formatoClave\n" +
                "\t\t\t\t\t\txmlns:ns11=\"http://www.rbm.com.co/esb/\">3DES\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns11:formatoClave>\n" +
                "\t\t\t\t</ns0:infoAutenticacion>\n" +
                "\t\t\t</ns0:infoMedioPago>\n" +
                "\t\t\t<ns0:infoCompra>\n" +
                "\t\t\t\t<ns0:montoTotal>5000</ns0:montoTotal>\n" +
                "\t\t\t\t<ns0:referencia>CPNJDQMEW4LV</ns0:referencia>\n" +
                "\t\t\t\t<ns0:cantidadCuotas>2</ns0:cantidadCuotas>\n" +
                "\t\t\t\t<ns0:infoFacilitador>\n" +
                "\t\t\t\t\t<ns12:marcTerminal\n" +
                "\t\t\t\t\t\txmlns:ns12=\"http://www.rbm.com.co/esb/\">BOLD*Stg Juan\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns12:marcTerminal>\n" +
                "\t\t\t\t\t<ns13:FacilitadorID\n" +
                "\t\t\t\t\t\txmlns:ns13=\"http://www.rbm.com.co/esb/\">260278\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns13:FacilitadorID>\n" +
                "\t\t\t\t\t<ns14:SubMerchID\n" +
                "\t\t\t\t\t\txmlns:ns14=\"http://www.rbm.com.co/esb/\">NDH86D9U04\n" +
                "\t\t\t\t\t\n" +
                "\t\t\t\t\t</ns14:SubMerchID>\n" +
                "\t\t\t\t</ns0:infoFacilitador>\n" +
                "\t\t\t</ns0:infoCompra>\n" +
                "\t\t</ns0:compraProcesarSolicitud>\n" +
                "\t</Body>\n" +
                "</Envelope>";
    }

    // China team
    public static String getBasicSOAPEnvelopChinaTeam() {
        return "<Envelope\n" +
                "\txmlns=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<Body\n" +
                "\t\txmlns:wstxns1=\"http://schemas.xmlsoap.org/soap/envelope/\" wstxns1:type=\"purchase\">\n" +
                "\t\t<wstxns2:compraProcesarSolicitud\n" +
                "\t\t\txmlns:wstxns2=\"http://www.rbm.com.co/esb/comercio/compra/\">\n" +
                "\t\t\t<wstxns2:cabeceraSolicitud>\n" +
                "\t\t\t\t<wstxns2:infoPuntoInteraccion>\n" +
                "\t\t\t\t\t<wstxns3:tipoTerminal\n" +
                "\t\t\t\t\t\txmlns:wstxns3=\"http://www.rbm.com.co/esb/comercio/\">WEB\n" +
                "\t\t\t\t\t</wstxns3:tipoTerminal>\n" +
                "\t\t\t\t\t<wstxns4:idTerminal\n" +
                "\t\t\t\t\t\txmlns:wstxns4=\"http://www.rbm.com.co/esb/comercio/\">SRB00085\n" +
                "\t\t\t\t\t</wstxns4:idTerminal>\n" +
                "\t\t\t\t\t<wstxns5:idAdquiriente\n" +
                "\t\t\t\t\t\txmlns:wstxns5=\"http://www.rbm.com.co/esb/comercio/\">10203040\n" +
                "\t\t\t\t\t</wstxns5:idAdquiriente>\n" +
                "\t\t\t\t\t<wstxns6:idTransaccionTerminal\n" +
                "\t\t\t\t\t\txmlns:wstxns6=\"http://www.rbm.com.co/esb/comercio/\">100001\n" +
                "\t\t\t\t\t</wstxns6:idTransaccionTerminal>\n" +
                "\t\t\t\t\t<wstxns7:modoCapturaPAN\n" +
                "\t\t\t\t\t\txmlns:wstxns7=\"http://www.rbm.com.co/esb/comercio/\">Manual\n" +
                "\t\t\t\t\t</wstxns7:modoCapturaPAN>\n" +
                "\t\t\t\t\t<wstxns8:capacidadPIN\n" +
                "\t\t\t\t\t\txmlns:wstxns8=\"http://www.rbm.com.co/esb/comercio/\">Virtual\n" +
                "\t\t\t\t\t</wstxns8:capacidadPIN>\n" +
                "\t\t\t\t</wstxns2:infoPuntoInteraccion>\n" +
                "\t\t\t</wstxns2:cabeceraSolicitud>\n" +
                "\t\t\t<wstxns2:idPersona>\n" +
                "\t\t\t\t<wstxns9:tipoDocumento\n" +
                "\t\t\t\t\txmlns:wstxns9=\"http://www.rbm.com.co/esb/comercio/\">CC\n" +
                "\t\t\t\t</wstxns9:tipoDocumento>\n" +
                "\t\t\t\t<wstxns10:numDocumento\n" +
                "\t\t\t\t\txmlns:wstxns10=\"http://www.rbm.com.co/esb/comercio/\">1081408954\n" +
                "\t\t\t\t</wstxns10:numDocumento>\n" +
                "\t\t\t</wstxns2:idPersona>\n" +
                "\t\t\t<wstxns2:infoMedioPago>\n" +
                "\t\t\t\t<wstxns2:idTarjetaCredito>\n" +
                "\t\t\t\t\t<wstxns11:franquicia\n" +
                "\t\t\t\t\t\txmlns:wstxns11=\"http://www.rbm.com.co/esb/\">VISA\n" +
                "\t\t\t\t\t</wstxns11:franquicia>\n" +
                "\t\t\t\t\t<wstxns12:numTarjeta\n" +
                "\t\t\t\t\t\txmlns:wstxns12=\"http://www.rbm.com.co/esb/\">4005990000001247\n" +
                "\t\t\t\t\t</wstxns12:numTarjeta>\n" +
                "\t\t\t\t\t<wstxns13:fechaExpiracion\n" +
                "\t\t\t\t\t\txmlns:wstxns13=\"http://www.rbm.com.co/esb/\">2025-12-31\n" +
                "\t\t\t\t\t</wstxns13:fechaExpiracion>\n" +
                "\t\t\t\t\t<wstxns14:codVerificacion\n" +
                "\t\t\t\t\t\txmlns:wstxns14=\"http://www.rbm.com.co/esb/\">124\n" +
                "\t\t\t\t\t</wstxns14:codVerificacion>\n" +
                "\t\t\t\t</wstxns2:idTarjetaCredito>\n" +
                "\t\t\t</wstxns2:infoMedioPago>\n" +
                "\t\t\t<wstxns2:infoCompra>\n" +
                "\t\t\t\t<wstxns2:montoTotal>10000.00</wstxns2:montoTotal>\n" +
                "\t\t\t\t<wstxns2:infoImpuestos>\n" +
                "\t\t\t\t\t<wstxns15:tipoImpuesto\n" +
                "\t\t\t\t\t\txmlns:wstxns15=\"http://www.rbm.com.co/esb/comercio/\">IVA\n" +
                "\t\t\t\t\t</wstxns15:tipoImpuesto>\n" +
                "\t\t\t\t\t<wstxns16:monto\n" +
                "\t\t\t\t\t\txmlns:wstxns16=\"http://www.rbm.com.co/esb/comercio/\">0.00\n" +
                "\t\t\t\t\t</wstxns16:monto>\n" +
                "\t\t\t\t</wstxns2:infoImpuestos>\n" +
                "\t\t\t\t<wstxns2:cantidadCuotas>1</wstxns2:cantidadCuotas>\n" +
                "\t\t\t\t<wstxns2:referencia>2b055320e4b542d2b990891bf</wstxns2:referencia>\n" +
                "\t\t\t</wstxns2:infoCompra>\n" +
                "\t\t</wstxns2:compraProcesarSolicitud>\n" +
                "\t</Body>\n" +
                "</Envelope>";
    }

    public static String getCleanBodyContent() {
        return "<ns0:compraProcesarSolicitud\n" +
                "\t\t\t\t\txmlns:ns0=\"http://www.rbm.com.co/esb/comercio/compra/\">\n" +
                "\t\t\t\t\t<ns0:cabeceraSolicitud>\n" +
                "\t\t\t\t\t\t<ns0:infoPuntoInteraccion>\n" +
                "\t\t\t\t\t\t\t<ns1:tipoTerminal\n" +
                "\t\t\t\t\t\t\t\txmlns:ns1=\"http://www.rbm.com.co/esb/comercio/\">POS\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns1:tipoTerminal>\n" +
                "\t\t\t\t\t\t\t<ns2:idTerminal\n" +
                "\t\t\t\t\t\t\t\txmlns:ns2=\"http://www.rbm.com.co/esb/comercio/\">SRB01589\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns2:idTerminal>\n" +
                "\t\t\t\t\t\t\t<ns3:idAdquiriente\n" +
                "\t\t\t\t\t\t\t\txmlns:ns3=\"http://www.rbm.com.co/esb/comercio/\">20304102\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns3:idAdquiriente>\n" +
                "\t\t\t\t\t\t\t<ns4:idTransaccionTerminal\n" +
                "\t\t\t\t\t\t\t\txmlns:ns4=\"http://www.rbm.com.co/esb/comercio/\">326945\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns4:idTransaccionTerminal>\n" +
                "\t\t\t\t\t\t\t<ns5:modoCapturaPAN\n" +
                "\t\t\t\t\t\t\t\txmlns:ns5=\"http://www.rbm.com.co/esb/comercio/\">Banda\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns5:modoCapturaPAN>\n" +
                "\t\t\t\t\t\t\t<ns6:capacidadPIN\n" +
                "\t\t\t\t\t\t\t\txmlns:ns6=\"http://www.rbm.com.co/esb/comercio/\">Permitido\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns6:capacidadPIN>\n" +
                "\t\t\t\t\t\t</ns0:infoPuntoInteraccion>\n" +
                "\t\t\t\t\t</ns0:cabeceraSolicitud>\n" +
                "\t\t\t\t\t<ns0:infoMedioPago>\n" +
                "\t\t\t\t\t\t<ns0:idTrack>\n" +
                "\t\t\t\t\t\t\t<ns7:Franquicia\n" +
                "\t\t\t\t\t\t\t\txmlns:ns7=\"http://www.rbm.com.co/esb/\">MasterCard\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns7:Franquicia>\n" +
                "\t\t\t\t\t\t\t<ns8:track\n" +
                "\t\t\t\t\t\t\t\txmlns:ns8=\"http://www.rbm.com.co/esb/\">2223590400108111=25121011111199911111\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns8:track>\n" +
                "\t\t\t\t\t\t\t<ns9:tipoCuenta\n" +
                "\t\t\t\t\t\t\t\txmlns:ns9=\"http://www.rbm.com.co/esb/\">Credito\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns9:tipoCuenta>\n" +
                "\t\t\t\t\t\t</ns0:idTrack>\n" +
                "\t\t\t\t\t\t<ns0:infoAutenticacion>\n" +
                "\t\t\t\t\t\t\t<ns10:clave\n" +
                "\t\t\t\t\t\t\t\txmlns:ns10=\"http://www.rbm.com.co/esb/\">26B03DA72C4B5F35\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns10:clave>\n" +
                "\t\t\t\t\t\t\t<ns11:formatoClave\n" +
                "\t\t\t\t\t\t\t\txmlns:ns11=\"http://www.rbm.com.co/esb/\">3DES\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns11:formatoClave>\n" +
                "\t\t\t\t\t\t</ns0:infoAutenticacion>\n" +
                "\t\t\t\t\t</ns0:infoMedioPago>\n" +
                "\t\t\t\t\t<ns0:infoCompra>\n" +
                "\t\t\t\t\t\t<ns0:montoTotal>5000</ns0:montoTotal>\n" +
                "\t\t\t\t\t\t<ns0:referencia>CPNJDQMEW4LV</ns0:referencia>\n" +
                "\t\t\t\t\t\t<ns0:cantidadCuotas>2</ns0:cantidadCuotas>\n" +
                "\t\t\t\t\t\t<ns0:infoFacilitador>\n" +
                "\t\t\t\t\t\t\t<ns12:marcTerminal\n" +
                "\t\t\t\t\t\t\t\txmlns:ns12=\"http://www.rbm.com.co/esb/\">BOLD*Stg Juan\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns12:marcTerminal>\n" +
                "\t\t\t\t\t\t\t<ns13:FacilitadorID\n" +
                "\t\t\t\t\t\t\t\txmlns:ns13=\"http://www.rbm.com.co/esb/\">260278\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns13:FacilitadorID>\n" +
                "\t\t\t\t\t\t\t<ns14:SubMerchID\n" +
                "\t\t\t\t\t\t\t\txmlns:ns14=\"http://www.rbm.com.co/esb/\">NDH86D9U04\n" +
                "                                        \n" +
                "\t\t\t\t\t\t\t</ns14:SubMerchID>\n" +
                "\t\t\t\t\t\t</ns0:infoFacilitador>\n" +
                "\t\t\t\t\t</ns0:infoCompra>\n" +
                "\t\t\t\t</ns0:compraProcesarSolicitud>";
    }
}
