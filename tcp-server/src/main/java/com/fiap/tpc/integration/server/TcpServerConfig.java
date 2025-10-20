package com.fiap.tpc.integration.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.integration.config.EnableIntegration;
import org.springframework.integration.dsl.IntegrationFlow;
import org.springframework.integration.dsl.IntegrationFlows;
import org.springframework.integration.ip.dsl.Tcp;
import org.springframework.integration.ip.tcp.connection.AbstractServerConnectionFactory;
import org.springframework.integration.ip.tcp.connection.TcpNioServerConnectionFactory;
import org.springframework.integration.ip.tcp.serializer.ByteArrayCrLfSerializer;

import javax.annotation.PostConstruct;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@Configuration
@EnableIntegration
public class TcpServerConfig {

	private static final Logger LOG = LoggerFactory.getLogger(TcpServerConfig.class);

	@Value("${tcp.server.port}")
	private int tcpServerPort;

	// A chave pública do cliente (em Base64) vem do application.properties
	@Value("${tcp.client.publicKey}")
	private String clientePublicKeyBase64;

	private KeyPair keyPairServidor;
	private PublicKey clientePublicKey;

	@PostConstruct
	public void initKeys() throws Exception {

		// Carrega chave privada de arquivo PEM
		PrivateKey privateKey = ClientServerCryptography.carregarChavePrivadaDePem("server_private.pem");
		PublicKey publicKey = ClientServerCryptography.carregarChavePublicaDePem("server_public.pem");
		keyPairServidor = new KeyPair(publicKey, privateKey);

		// Chave pública do cliente
		byte[] pubKeyBytes = Base64.getDecoder().decode(clientePublicKeyBase64);
		clientePublicKey = ClientServerCryptography.bytesParaChave(pubKeyBytes);
	}


	@Bean
	public IntegrationFlow commandServerFlow() {
		return IntegrationFlows.from(Tcp.inboundGateway(serverConnectionFactory()))
				.handle((payload, headers) -> {
					try {
						// Lê a mensagem cifrada
						String mensagemCifrada = (payload instanceof byte[])
								? new String((byte[]) payload)
								: payload.toString();

						LOG.info(" Mensagem cifrada recebida do cliente: {}", mensagemCifrada);

						// Decifra com a chave privada do servidor
						String mensagemDecifrada = ClientServerCryptography.decifrar(
								mensagemCifrada, keyPairServidor.getPrivate());
						LOG.info(" Mensagem decifrada: {}", mensagemDecifrada);

						// Processa a mensagem
						String resposta = "Servidor recebeu: [" + mensagemDecifrada + "] com sucesso!";
						LOG.info(" Resposta cifrada enviada ao cliente: {}", resposta);

						// Cifra a resposta com a chave pública do cliente
						String respostaCifrada = ClientServerCryptography.cifrar(
								resposta, clientePublicKey);
						LOG.info(" Resposta cifrada enviada ao cliente: {}", respostaCifrada);

						return respostaCifrada;

					} catch (Exception e) {
						LOG.error(" Erro ao processar mensagem criptografada", e);
						throw new RuntimeException("Erro ao processar mensagem segura", e);
					}
				})
				.get();
	}

	// Configuração do servidor TCP
	public AbstractServerConnectionFactory serverConnectionFactory() {
		TcpNioServerConnectionFactory tcpServer = new TcpNioServerConnectionFactory(tcpServerPort);
		tcpServer.setSingleUse(true);
		tcpServer.setSerializer(codec());
		tcpServer.setDeserializer(codec());
		return tcpServer;
	}

	// Serializador CRLF (igual ao do cliente)
	public ByteArrayCrLfSerializer codec() {
		ByteArrayCrLfSerializer crLfSerializer = new ByteArrayCrLfSerializer();
		crLfSerializer.setMaxMessageSize(204800000);
		return crLfSerializer;
	}
}

