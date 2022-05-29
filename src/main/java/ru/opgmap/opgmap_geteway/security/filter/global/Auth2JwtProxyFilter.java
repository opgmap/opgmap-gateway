package ru.opgmap.opgmap_geteway.security.filter.global;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class Auth2JwtProxyFilter implements WebFilter {

    public static final String ROLES = "roles";
    public static final String AUTH = HttpHeaders.AUTHORIZATION;
    public static final String AUTH_JWT = "JWT-X-TOKEN";

    private final AuthConfiguration auth;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        Optional<String> oAuth2accessToken = Optional.ofNullable(request.getHeaders().getFirst(AUTH));
        String jwtToken;

        if (oAuth2accessToken.isPresent()) {
            try {
                JWT jwt = JWTParser.parse(oAuth2accessToken.get().split(" ")[1]);
                JWTClaimsSet oAuthClaims = jwt.getJWTClaimsSet();

                JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                        .subject(oAuthClaims.getSubject())
                        .jwtID(oAuthClaims.getJWTID())
                        .issueTime(oAuthClaims.getIssueTime())
                        .expirationTime(oAuthClaims.getExpirationTime())
                        .audience(auth.aud)
                        .issuer(auth.iss)
                        .claim(ROLES, ((JSONObject) oAuthClaims.getClaim("realm_access")).get(ROLES))
                        .build();

                JWSSigner signer = new MACSigner(auth.secretKey);
                JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256),
                        new Payload(jwtClaims.toJSONObject()));

                jwsObject.sign(signer);
                jwtToken = jwsObject.serialize();

                request.mutate().header(AUTH_JWT, "Bearer " + jwtToken);
                log.info("Added Additional JWT [{}]", jwtToken);

            } catch (ParseException | JOSEException e) {
                log.error("Jwt error occurred", new IllegalArgumentException(e));
            }
        } else {
            log.warn("{} header is not present. skip", AUTH);
        }
        return chain.filter(exchange);
    }

}
