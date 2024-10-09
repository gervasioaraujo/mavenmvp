package com.liquido.mvp.controller;

import com.liquido.mvp.service.RedebanService;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RedebanController {

    @Autowired
    RedebanService redebanService;

    @GetMapping("/mvp/v0/redeban")
    public String redebanV0() {
        /*
         * - Usa um SOAP message limpo e envia para o server na porta 443
         * ******** With "soapenv:" prefix
         * */
        System.out.println("\n\n => Running V0 route...");
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
        * // ******** With "soap-env:" prefix
        * */
        System.out.println("\n\n => Running V1 route...");
        try {
            return redebanService.executeSOAPAndHttpsRequest_V1_V5(true);
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
         * // ******** With "soap-env:" prefix
         * */
        System.out.println("\n\n => Running V2 route...");
        try {
            return redebanService.executeSOAPAndHttpsRequest_V2_V6(true);
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
         * // ******** With "soap-env:" prefix
         * */
        System.out.println("\n\n => Running V3 route...");
        try {
            return redebanService.executeWss4jSOAPAndHttpsRequest(false, true);
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
         * // ******** With "soap-env:" prefix
         * */
        System.out.println("\n\n => Running V4 route...");
        try {
            return redebanService.executeWss4jSOAPAndHttpsRequest(true, true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/mvp/v5/redeban")
    public String redebanV5() {
        /*
         * - Usa uma chave efêmera estática;
         * - Usa um vetor de inicialização estático;
         * - Criptografa o body incluindo a tag <soap-env: Body>;
         * - Usa o ski estático = "MEm79zLpk2XK2hXT3uPyx6VB0Og=";
         * - Envia o xml somente cifrado.
         * // ******** With "soapenv:" prefix
         * */
        System.out.println("\n\n => Running V5 route...");
        try {
            return redebanService.executeSOAPAndHttpsRequest_V1_V5(false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/mvp/v6/redeban")
    public String redebanV6() {
        /*
         * - Usa uma chave efêmera gerada dinamicamente;
         * - Usa um vetor de inicialização gerado dinamicamente;
         * - Criptografa o body não incluindo a tag <soap-env: Body> (somente o conteúdo dentro do body);
         * - Usa o ski estático = "MEm79zLpk2XK2hXT3uPyx6VB0Og=";
         * - Envia o xml somente cifrado.
         * // ******** With "soapenv:" prefix
         * */
        System.out.println("\n\n => Running V6 route...");
        try {
            return redebanService.executeSOAPAndHttpsRequest_V2_V6(false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/mvp/v7/redeban")
    public String redebanV7() {
        /*
         * - Usa a lib wss4j-2.4.3 (mesmo código criado pelo time da China para cifrar e assinar a mensagem SOAP);
         *
         * - Usa uma chave efêmera gerada dinamicamente (o iv deve ser gerenciado pela própria lib wss4j);
         * - Criptografa o body não incluindo a tag <soap-env: Body> (somente o conteúdo dentro do body);
         * - Usa uma constante para definir o ski, mas no final o resultado é = "MEm79zLpk2XK2hXT3uPyx6VB0Og=";
         * - Envia o xml somente cifrado.
         * // ******** With "soapenv:" prefix
         * */
        System.out.println("\n\n => Running V7 route...");
        try {
            return redebanService.executeWss4jSOAPAndHttpsRequest(false, false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/mvp/v8/redeban")
    public String redebanV8() {
        /*
         * - Usa a lib wss4j-2.4.3 (mesmo código criado pelo time da China para cifrar e assinar a mensagem SOAP);
         *
         * - Usa uma chave efêmera gerada dinamicamente (o iv deve ser gerenciado pela própria lib wss4j);
         * - Criptografa o body não incluindo a tag <soap-env: Body> (somente o conteúdo dentro do body);
         * - Usa uma constante para definir o ski, mas no final o resultado é = "MEm79zLpk2XK2hXT3uPyx6VB0Og=";
         * - Envia o xml cifrado e assinado.
         * // ******** With "soapenv:" prefix
         * */
        System.out.println("\n\n => Running V8 route...");
        try {
            return redebanService.executeWss4jSOAPAndHttpsRequest(true, false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
