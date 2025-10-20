package com.fiap.tpc.integration.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.integration.annotation.IntegrationComponentScan;
import org.springframework.integration.channel.DirectChannel;
import org.springframework.integration.config.EnableIntegration;
import org.springframework.integration.dsl.IntegrationFlow;
import org.springframework.integration.dsl.IntegrationFlows;
import org.springframework.integration.ip.dsl.Tcp;
import org.springframework.integration.ip.tcp.connection.*;
import org.springframework.integration.ip.tcp.serializer.ByteArrayCrLfSerializer;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHandler;
import org.springframework.messaging.MessagingException;

import javax.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@Configuration
@EnableIntegration
@IntegrationComponentScan
public class TcpClientConfig {

	private static final Logger LOG = LoggerFactory.getLogger(TcpClientConfig.class);

	@Value("${tcp.server.address}")
	private String tcpServerAddress;

	@Value("${tcp.server.port}")
	private int tcpServerPort;

	@Value("${tcp.client.timeout}")
	private int tcpClientTimeout;

	@Value("${tcp.client.poolSize}")
	private int tcpClientPoolSize;

	// Chave pública do servidor (Base64 no application.properties)
	@Value("${tcp.server.publicKey}")
	private String servidorPublicKeyBase64;

	private PublicKey servidorPublicKey;
	private KeyPair keyPairCliente; // cliente_public.pem + cliente_private.pem

	@PostConstruct
	public void initKeys() throws Exception {
		// Carrega chave pública do servidor
		byte[] pubKeyBytes = Base64.getDecoder().decode(servidorPublicKeyBase64);
		servidorPublicKey = ClientServerCryptography.bytesParaChave(pubKeyBytes);

		// Carrega chaves do cliente (arquivos PEM)
		PrivateKey privateKey = ClientServerCryptography.carregarChavePrivadaDePem("client_private.pem");
		PublicKey publicKey = ClientServerCryptography.carregarChavePublicaDePem("client_public.pem");
		keyPairCliente = new KeyPair(publicKey, privateKey);

		LOG.info(" Chaves RSA do cliente carregadas com sucesso.");
	}

	// Canal principal
	@Bean
	public org.springframework.messaging.MessageChannel tcpClientChannel() {
		return new DirectChannel();
	}

	// Fluxo principal
	@Bean
	public IntegrationFlow tcpClientToServerFlow() {
		return IntegrationFlows.from("tcpClientChannel")
				.transform(mensagem -> {
					try {
						String msgOriginal = mensagem.toString();
						LOG.info(" Mensagem original: {}", msgOriginal);

						// Cifra com a chave pública do servidor
						String cifrada = ClientServerCryptography.cifrar(msgOriginal, servidorPublicKey);
						LOG.info(" Mensagem cifrada (Base64): {}", cifrada);

						return cifrada.getBytes(StandardCharsets.UTF_8);
					} catch (Exception e) {
						throw new RuntimeException("Erro ao cifrar mensagem", e);
					}
				})
				.handle(Tcp.outboundGateway(clientConnectionFactory()).remoteTimeout(tcpClientTimeout))
				.transform(resposta -> {
					try {
						// Converte bytes recebidos em String (Base64)
						String respostaCifrada = (resposta instanceof byte[])
								? new String((byte[]) resposta, StandardCharsets.UTF_8).trim()
								: resposta.toString().trim();

						LOG.info(" Resposta cifrada recebida do servidor: {}", respostaCifrada);

						// Decifra com a chave privada do cliente
						String respostaDecifrada = ClientServerCryptography.decifrar(respostaCifrada, keyPairCliente.getPrivate());
						LOG.info("️ Resposta decifrada: {}", respostaDecifrada);

						return respostaDecifrada;
					} catch (Exception e) {
						LOG.error(" Erro ao decifrar resposta do servidor", e);
						throw new RuntimeException("Erro ao decifrar resposta do servidor", e);
					}
				})
				.get();
	}

	// Canal de erro
	@Bean
	public org.springframework.messaging.MessageChannel tcpClientErrorChannel() {
		return new DirectChannel();
	}

	@Bean
	public IntegrationFlow tcpClientErrorChannelFlow() {
		return IntegrationFlows.from("tcpClientErrorChannel")
				.handle(new MessageHandler() {
					@Override
					public void handleMessage(Message<?> message) throws MessagingException {
						LOG.error(" Erro na comunicação TCP: {}", message.getPayload());
					}
				})
				.get();
	}

	// Configuração TCP
	public AbstractClientConnectionFactory clientConnectionFactory() {
		TcpNioClientConnectionFactory factory =
				new TcpNioClientConnectionFactory(tcpServerAddress, tcpServerPort);
		factory.setUsingDirectBuffers(true);
		factory.setSingleUse(true);
		factory.setSerializer(codec());
		factory.setDeserializer(codec());
		return new CachingClientConnectionFactory(factory, tcpClientPoolSize);
	}

	public ByteArrayCrLfSerializer codec() {
		ByteArrayCrLfSerializer crLfSerializer = new ByteArrayCrLfSerializer();
		crLfSerializer.setMaxMessageSize(204800000);
		return crLfSerializer;
	}
}
