package com.fiap.tpc.integration;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class TpcClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(TpcClientApplication.class, args);
	}

}
