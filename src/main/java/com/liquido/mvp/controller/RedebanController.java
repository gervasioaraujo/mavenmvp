package com.liquido.mvp.controller;

import com.liquido.mvp.service.RedebanService;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RedebanController {

    @Autowired
    RedebanService redebanService;

    @GetMapping("/mvp/br1/redeban")
    public String redebanBR1() {
        /*
         * - Usa a lib wss4j-2.4.3 (código criado pelo time BR);
         *
         * - Usa uma chave efêmera gerada dinamicamente (o iv deve ser gerenciado pela própria lib wss4j);
         * - Criptografa o body não incluindo a tag <soap-env: Body> (somente o conteúdo dentro do body);
         *
         * - Usa uma constante para definir o ski, mas no final o resultado é = "7iAhGawInE+OftuL3P2it6GB/0U="; ?????????????????
         *
         * - Envia o xml somente cifrado.
         * // ******** With "soap-env:" prefix
         * */
        System.out.println("\n\n => Running BR1 route...");
        try {
            return redebanService.executeWss4jSOAPAndHttpsRequest_BR(false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/mvp/br2/redeban")
    public String redebanBR2() {
        /*
         * - Usa a lib wss4j-2.4.3 (código criado pelo time BR);
         *
         * - Usa uma chave efêmera gerada dinamicamente (o iv deve ser gerenciado pela própria lib wss4j);
         * - Criptografa o body não incluindo a tag <soap-env: Body> (somente o conteúdo dentro do body);
         *
         * - Usa uma constante para definir o ski, mas no final o resultado é = "7iAhGawInE+OftuL3P2it6GB/0U="; ?????????????????
         *
         * - Envia o xml cifrado e assinado.
         * // ******** With "soap-env:" prefix
         * */
        System.out.println("\n\n => Running BR2 route...");
        try {
            return redebanService.executeWss4jSOAPAndHttpsRequest_BR(true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
