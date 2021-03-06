package ru.opgmap.opgmap_geteway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

@SpringBootApplication
@EnableEurekaClient
public class OpgmapGetewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(OpgmapGetewayApplication.class, args);
    }

}
