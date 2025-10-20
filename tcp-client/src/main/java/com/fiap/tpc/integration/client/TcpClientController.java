package com.fiap.tpc.integration.client;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

@RestController
@RequestMapping("/tcp")
public class TcpClientController {

    @Autowired
    private TcpClientGateway gateway;

    @PostMapping("/send")
    public String sendMessage(@RequestBody String message) {
        try {
            String response = gateway.send(message);
            return "Resposta do servidor TCP: " + response;
        } catch (Exception e) {
            return "Erro ao enviar: " + e.getMessage();
        }
    }
}
