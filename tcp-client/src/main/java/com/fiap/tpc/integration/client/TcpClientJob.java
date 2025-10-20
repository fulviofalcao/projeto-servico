package com.fiap.tpc.integration.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class TcpClientJob {

    private static final Logger LOG = LoggerFactory.getLogger(TcpClientJob.class);

    @Value("${CLIENT_ID:default}")
    private String clientId;

    @Autowired
    private TcpClientGateway gateway;

    /**
     * Executa a cada 1 minuto (60000 ms)
     */
//    @Scheduled(cron = "0 * * * * *")
    public void sendPeriodicMessage() {
        String message = "Mensagem do cliente " + clientId + " - " + System.currentTimeMillis();
        LOG.info(message);
        try {
            String response = gateway.send(message);
            LOG.info(" Resposta do servidor TCP: {}" + response);
        } catch (Exception e) {
            LOG.error(" Erro ao enviar mensagem TCP: {}" + e.getMessage());
        }
    }
}
