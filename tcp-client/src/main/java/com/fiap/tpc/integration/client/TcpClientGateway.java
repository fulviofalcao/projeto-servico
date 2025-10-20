package com.fiap.tpc.integration.client;

import org.springframework.integration.annotation.MessagingGateway;

@MessagingGateway(defaultRequestChannel = "tcpClientChannel", errorChannel = "tcpClientErrorChannel")
public interface TcpClientGateway {
	String send(String message);
}
