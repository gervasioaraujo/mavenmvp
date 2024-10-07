package com.liquido.mvp.utils;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
// import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
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

    private static final String TERMINAL_TYPE = "WEB";
    private static final String TERMINAL_ID = "SRB00085";
    private static final String ACQUIRER_ID = "10203040";
    private static final String TERMINAL_TRANSACTION_ID = "100001";
    private static final String PAN_CAPTURE_MODE = "Manual";
    private static final String PIN_CAPACITY = "Virtual";

    private static final String DOCUMENT_TYPE = "CC";
    private static final String DOCUMENT_NUMBER = "1000000001";

    private static final String CARD_BRAND = "VISA";
    private static final String CARD_NUMBER = "4005990000001247";
    private static final String CARD_EXPIRATION_DATE = "2025-12-31";
    private static final String CARD_CVC = "124";

    private static final String CLEAN_CONTENT_TAG_BODY = "<ns0:compraProcesarSolicitud xmlns:ns0=\"http://www.rbm.com.co/esb/comercio/compra/\"><ns0:cabeceraSolicitud><ns0:infoPuntoInteraccion><ns1:tipoTerminal xmlns:ns1=\"http://www.rbm.com.co/esb/comercio/\">WEB</ns1:tipoTerminal><ns2:idTerminal xmlns:ns2=\"http://www.rbm.com.co/esb/comercio/\">SRB00085</ns2:idTerminal><ns3:idAdquiriente xmlns:ns3=\"http://www.rbm.com.co/esb/comercio/\">10203040</ns3:idAdquiriente><ns4:idTransaccionTerminal xmlns:ns4=\"http://www.rbm.com.co/esb/comercio/\">100001</ns4:idTransaccionTerminal><ns5:modoCapturaPAN xmlns:ns5=\"http://www.rbm.com.co/esb/comercio/\">Manual</ns5:modoCapturaPAN><ns6:capacidadPIN xmlns:ns6=\"http://www.rbm.com.co/esb/comercio/\">Virtual</ns6:capacidadPIN></ns0:infoPuntoInteraccion></ns0:cabeceraSolicitud><ns0:infoMedioPago><ns0:idTarjetaCredito><ns7:franquicia xmlns:ns7=\"http://www.rbm.com.co/esb/\">VISA</ns7:franquicia><ns8:numTarjeta xmlns:ns8=\"http://www.rbm.com.co/esb/\">4005990000001247</ns8:numTarjeta><ns9:fechaExpiracion xmlns:ns9=\"http://www.rbm.com.co/esb/\">2025-12-31</ns9:fechaExpiracion><ns10:codVerificacion xmlns:ns10=\"http://www.rbm.com.co/esb/\">124</ns10:codVerificacion></ns0:idTarjetaCredito></ns0:infoMedioPago><ns0:infoCompra><ns0:montoTotal>5000</ns0:montoTotal><ns0:referencia>CPNJDQMEW4LV</ns0:referencia><ns0:cantidadCuotas>2</ns0:cantidadCuotas><ns0:infoFacilitador><ns12:marcTerminal xmlns:ns12=\"http://www.rbm.com.co/esb/\">BOLD*Stg Juan</ns12:marcTerminal><ns13:FacilitadorID xmlns:ns13=\"http://www.rbm.com.co/esb/\">260278</ns13:FacilitadorID><ns14:SubMerchID xmlns:ns14=\"http://www.rbm.com.co/esb/\">NDH86D9U04</ns14:SubMerchID></ns0:infoFacilitador></ns0:infoCompra></ns0:compraProcesarSolicitud>";

    public static String getXmlSOAPEnvelopClean() {
        return String.format(
                "<soap-env:Envelope xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:soap-env=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap-env:Header><wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><wsse:UsernameToken><wsse:Username>TestLiquido</wsse:Username><wsse:Password>Liquido.2023</wsse:Password></wsse:UsernameToken></wsse:Security></soap-env:Header>\n<soap-env:Body ns15:Id=\"id-4f5036d7-4c08-45ab-a484-7ce5411d097e\" xmlns:ns15=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><ns0:compraProcesarSolicitud xmlns:ns0=\"http://www.rbm.com.co/esb/comercio/compra/\">\n>%s</soap-env:Body></soap-env:Envelope>",
                CLEAN_CONTENT_TAG_BODY
        );
    }

    public static String getXmlBodyCleanIncludingBodyTag() {
        return String.format("<soap-env:Body>%s</soap-env:Body>", CLEAN_CONTENT_TAG_BODY);
    }

    public static String getXmlBodyCleanExcludingBodyTag() {
        return CLEAN_CONTENT_TAG_BODY;
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

    public static String getXmlSOAPEnvelopOnlyCiphedBody(
            final String cipherBodyValue,
            final String cipherEphemeralKeyValue,
            final String ski
    ) {
        return String.format("<soap-env:Envelope xmlns:soap-env=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap-env:Header><wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" soap-env:mustUnderstand=\"1\"><xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"EK-52c73e2b-e722-434b-bd23-d0a99191e99f\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><wsse:SecurityTokenReference><wsse:KeyIdentifier EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\">%s</wsse:KeyIdentifier></wsse:SecurityTokenReference></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData><xenc:ReferenceList><xenc:DataReference URI=\"#ED-d99068fc-bf0e-41f1-b79b-3503e3dd72fd\"/></xenc:ReferenceList></xenc:EncryptedKey><wsse:UsernameToken wsu:Id=\"UsernameToken-7bb5307f-92d9-4cbb-8288-4351a7bacaaa\"><wsse:Username>%s</wsse:Username><wsse:Password Type=\"PasswordText\">%s</wsse:Password></wsse:UsernameToken></wsse:Security></soap-env:Header><soap-env:Body><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"ED-d99068fc-bf0e-41f1-b79b-3503e3dd72fd\" Type=\"http://www.w3.org/2001/04/xmlenc#Content\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></soap-env:Body></soap-env:Envelope>",
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

    /*public static String encryptSOAPBodyV1(String bodyClean, String ephemeralKey, String initVector) {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(ephemeralKey.getBytes("UTF-8"), "AES");
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));

            // "RSA-OAEP-MGF1 with AES-256-CBC" or 3DES-CBC with RSA-1_5 (RSA PKCS #1 v1.5)
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING"); // xml -> EncryptionMethod = aes256-cbc
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(bodyClean.getBytes());

            return Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }*/

    /*public static String encryptEphemeralKeyV1(String ephemeralKey, String publicKeyPath) {
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
    }*/

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

    /*private static String bytesToHex(byte[] encodedhash) {
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
    }*/

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

    public static String getBasicSOAPEnvelopBrazilTeam() {
        return String.format("<Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"><Body xmlns:wstxns1=\"http://schemas.xmlsoap.org/soap/envelope/\" wstxns1:type=\"purchase\">%s</Body></Envelope>",
                CLEAN_CONTENT_TAG_BODY);
    }

    /*// China team
    public static String getBasicSOAPEnvelopChinaTeam() {
        return "<Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"><Body xmlns:wstxns1=\"http://schemas.xmlsoap.org/soap/envelope/\" wstxns1:type=\"purchase\"><wstxns2:compraProcesarSolicitud xmlns:wstxns2=\"http://www.rbm.com.co/esb/comercio/compra/\"><wstxns2:cabeceraSolicitud><wstxns2:infoPuntoInteraccion><wstxns3:tipoTerminal xmlns:wstxns3=\"http://www.rbm.com.co/esb/comercio/\">WEB</wstxns3:tipoTerminal><wstxns4:idTerminal xmlns:wstxns4=\"http://www.rbm.com.co/esb/comercio/\">SRB00085</wstxns4:idTerminal><wstxns5:idAdquiriente xmlns:wstxns5=\"http://www.rbm.com.co/esb/comercio/\">10203040</wstxns5:idAdquiriente><wstxns6:idTransaccionTerminal xmlns:wstxns6=\"http://www.rbm.com.co/esb/comercio/\">100001</wstxns6:idTransaccionTerminal><wstxns7:modoCapturaPAN xmlns:wstxns7=\"http://www.rbm.com.co/esb/comercio/\">Manual</wstxns7:modoCapturaPAN><wstxns8:capacidadPIN xmlns:wstxns8=\"http://www.rbm.com.co/esb/comercio/\">Virtual</wstxns8:capacidadPIN></wstxns2:infoPuntoInteraccion></wstxns2:cabeceraSolicitud><wstxns2:idPersona><wstxns9:tipoDocumento xmlns:wstxns9=\"http://www.rbm.com.co/esb/comercio/\">CC</wstxns9:tipoDocumento><wstxns10:numDocumento xmlns:wstxns10=\"http://www.rbm.com.co/esb/comercio/\">1081408954</wstxns10:numDocumento></wstxns2:idPersona><wstxns2:infoMedioPago><wstxns2:idTarjetaCredito><wstxns11:franquicia xmlns:wstxns11=\"http://www.rbm.com.co/esb/\">VISA</wstxns11:franquicia><wstxns12:numTarjeta xmlns:wstxns12=\"http://www.rbm.com.co/esb/\">4005990000001247</wstxns12:numTarjeta><wstxns13:fechaExpiracion xmlns:wstxns13=\"http://www.rbm.com.co/esb/\">2025-12-31</wstxns13:fechaExpiracion><wstxns14:codVerificacion xmlns:wstxns14=\"http://www.rbm.com.co/esb/\">124</wstxns14:codVerificacion></wstxns2:idTarjetaCredito></wstxns2:infoMedioPago><wstxns2:infoCompra><wstxns2:montoTotal>10000.00</wstxns2:montoTotal><wstxns2:infoImpuestos><wstxns15:tipoImpuesto xmlns:wstxns15=\"http://www.rbm.com.co/esb/comercio/\">IVA</wstxns15:tipoImpuesto><wstxns16:monto xmlns:wstxns16=\"http://www.rbm.com.co/esb/comercio/\">0.00</wstxns16:monto></wstxns2:infoImpuestos><wstxns2:cantidadCuotas>1</wstxns2:cantidadCuotas><wstxns2:referencia>2b055320e4b542d2b990891bf</wstxns2:referencia></wstxns2:infoCompra></wstxns2:compraProcesarSolicitud></Body></Envelope>";
    }*/

}
