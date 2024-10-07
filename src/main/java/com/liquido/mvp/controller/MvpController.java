package com.liquido.mvp.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;

import javax.xml.soap.SOAPException;

import java.io.BufferedReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import com.liquido.mvp.service.RedebanService;
import com.liquido.mvp.utils.RedebanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MvpController {

    @Autowired
    RedebanService redebanService;

    @GetMapping("/mvp/v0/redeban")
    public String redebanV0() {
        /*
         * - Usa um SOAP message limpo e envia para o server na porta 443
         * */
        try {
            return redebanService.executeSOAPAndHttpsRequestV0();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/mvp/v1/redeban")
    public String redebanV1() {
        /*
        * - Usa uma chave efêmera estática;
        * - Usa um vetor de inicialização estático;
        * - Criptografa o body incluindo a tag <soap-env: Body>;
        * - Usa o ski estático = "MEm79zLpk2XK2hXT3uPyx6VB0Og=";
        * - Envia o xml somente cifrado.
        * */
        try {
            return redebanService.executeSOAPAndHttpsRequestV1();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/mvp/v2/redeban")
    public String redebanV2() {
        /*
         * - Usa uma chave efêmera gerada dinamicamente;
         * - Usa um vetor de inicialização gerado dinamicamente;
         * - Criptografa o body não incluindo a tag <soap-env: Body> (somente o conteúdo dentro do body);
         * - Usa o ski estático = "MEm79zLpk2XK2hXT3uPyx6VB0Og=";
         * - Envia o xml somente cifrado.
         * */
        try {
            return redebanService.executeSOAPAndHttpsRequestV2();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /*@GetMapping("/mvp/v3/redeban")
    public String redebanV3() {
        try {
            return redebanService.executeSOAPAndHttpsRequestV3();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }*/

    @GetMapping("/mvp/v3/redeban")
    public String redebanV3() {
        /*
         * - Usa a lib wss4j-2.4.3 (mesmo código criado pelo time da China para cifrar e assinar a mensagem SOAP);
         *
         * - Usa uma chave efêmera gerada dinamicamente (o iv deve ser gerenciado pela própria lib wss4j);
         * - Criptografa o body não incluindo a tag <soap-env: Body> (somente o conteúdo dentro do body);
         * - Usa uma constante para definir o ski, mas no final o resultado é = "MEm79zLpk2XK2hXT3uPyx6VB0Og=";
         * - Envia o xml somente cifrado.
         * */
        try {
            return redebanService.executeWss4jSOAPAndHttpsRequest(false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/mvp/v4/redeban")
    public String redebanV4() {
        /*
         * - Usa a lib wss4j-2.4.3 (mesmo código criado pelo time da China para cifrar e assinar a mensagem SOAP);
         *
         * - Usa uma chave efêmera gerada dinamicamente (o iv deve ser gerenciado pela própria lib wss4j);
         * - Criptografa o body não incluindo a tag <soap-env: Body> (somente o conteúdo dentro do body);
         * - Usa uma constante para definir o ski, mas no final o resultado é = "MEm79zLpk2XK2hXT3uPyx6VB0Og=";
         * - Envia o xml cifrado e assinado.
         * */
        try {
            return redebanService.executeWss4jSOAPAndHttpsRequest(true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
