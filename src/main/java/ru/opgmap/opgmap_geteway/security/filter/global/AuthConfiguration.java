package ru.opgmap.opgmap_geteway.security.filter.global;

import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "auth.jwt")
@Setter
public class AuthConfiguration {

    public String secretKey;

    public String aud;

    public String iss;


}
