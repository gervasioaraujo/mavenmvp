package com.liquido.mvp.utils.crypto;

public class TripleDESCBCCrypto {

    /*
    * Explicação:
    Geração da chave AES efêmera: A chave é gerada dinamicamente para cada execução do código usando KeyGenerator com o algoritmo AES e tamanho de 256 bits.
    Geração do IV: O vetor de inicialização (IV) de 128 bits é gerado aleatoriamente e é necessário para o modo CBC (Cipher Block Chaining).
    Criptografia com AES-256-CBC: O Cipher é inicializado para criptografar com o modo AES/CBC/PKCS5Padding. A chave gerada e o IV são utilizados para criptografar a string.
    Codificação Base64: Tanto o texto criptografado quanto o IV são codificados em Base64 para facilitar o armazenamento ou transmissão.

    Esse código é um exemplo básico para criptografar uma string com AES-256-CBC e uma chave efêmera. Certifique-se de que o algoritmo AES-256 esteja habilitado no seu ambiente JDK, pois ele pode exigir bibliotecas de extensão de política de criptografia de força total (JCE Unlimited Strength Jurisdiction Policy Files).
    * */
}

