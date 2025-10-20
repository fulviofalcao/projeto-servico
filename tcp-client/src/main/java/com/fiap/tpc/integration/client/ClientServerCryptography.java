package com.fiap.tpc.integration.client;

import javax.crypto.Cipher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ClientServerCryptography {

    // Gera par RSA
    public static KeyPair gerarChavesPublicoPrivada() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    // Converte bytes para chave pública
    public static PublicKey bytesParaChave(byte[] pubKeyBytes) throws Exception {
        return KeyFactory.getInstance("RSA")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(pubKeyBytes));
    }

    // Cifra mensagem usando AES + RSA
    public static String cifrar(String texto, PublicKey chavePublicaRSA) throws Exception {
        // Gera chave AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey chaveAES = keyGen.generateKey();

        // Cifra o texto com AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, chaveAES, ivSpec);
        byte[] textoCifrado = aesCipher.doFinal(texto.getBytes());

        // Cifra a chave AES com RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, chavePublicaRSA);
        byte[] chaveAESCifrada = rsaCipher.doFinal(chaveAES.getEncoded());

        // Concatena: chaveAESCifrada | iv | textoCifrado
        String pacote = Base64.getEncoder().encodeToString(chaveAESCifrada)
                + ":" + Base64.getEncoder().encodeToString(iv)
                + ":" + Base64.getEncoder().encodeToString(textoCifrado);

        return pacote;
    }

    // Decifra o pacote (RSA + AES)
    public static String decifrar(String pacote, PrivateKey chavePrivadaRSA) throws Exception {
        String[] partes = pacote.split(":");
        byte[] chaveAESCifrada = Base64.getDecoder().decode(partes[0]);
        byte[] iv = Base64.getDecoder().decode(partes[1]);
        byte[] textoCifrado = Base64.getDecoder().decode(partes[2]);

        // Decifra chave AES com RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, chavePrivadaRSA);
        byte[] chaveAESBytes = rsaCipher.doFinal(chaveAESCifrada);
        SecretKey chaveAES = new javax.crypto.spec.SecretKeySpec(chaveAESBytes, "AES");

        // Decifra texto com AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, chaveAES, new IvParameterSpec(iv));
        byte[] textoDecifrado = aesCipher.doFinal(textoCifrado);

        return new String(textoDecifrado);
    }

    public static PrivateKey carregarChavePrivadaDePem(String caminho) throws Exception {
        String keyPem = lerArquivoPem(caminho);
        keyPem = keyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", ""); // remove quebras de linha e espaços

        byte[] keyBytes = Base64.getDecoder().decode(keyPem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    /**
     * Carrega uma chave pública RSA de um arquivo PEM (X.509)
     *
     * @param caminho caminho do arquivo .pem
     * @return PublicKey pronta para uso
     */
    public static PublicKey carregarChavePublicaDePem(String caminho) throws Exception {
        String keyPem = lerArquivoPem(caminho);
        keyPem = keyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(keyPem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    /**
     * Lê o conteúdo completo de um arquivo PEM e retorna como string
     */
    private static String lerArquivoPem(String caminho) throws IOException {
        return new String(Files.readAllBytes(Paths.get(caminho)), StandardCharsets.UTF_8);
    }
}
