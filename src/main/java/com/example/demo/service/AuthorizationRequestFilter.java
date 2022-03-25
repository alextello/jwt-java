package com.example.demo.service;

import com.example.demo.RsaKeyProducer;
import com.example.demo.interfaces.jwtIn;
import org.jose4j.jwt.consumer.JwtConsumer;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

@Provider
@jwtIn
public class AuthorizationRequestFilter implements ContainerRequestFilter {

    private static final String AUTHENTICATION_SCHEME = "Bearer";
    @Override
    public void filter(ContainerRequestContext request) throws IOException {
        // Get the Authorization header from the request
        String authorizationHeader =
                request.getHeaderString(HttpHeaders.AUTHORIZATION);

        // Validate the Authorization header
        if (!isTokenBasedAuthentication(authorizationHeader)) {
            abortWithUnauthorized(request);
            return;
        }

        // Extract the token from the Authorization header
        String token = authorizationHeader
                .substring(AUTHENTICATION_SCHEME.length()).trim();

        try {

            RsaKeyProducer rsaKeyProducer = new RsaKeyProducer();
            JwtConsumer signatureVerified = rsaKeyProducer.validateToken(token);
            //boolean signatureVerified = jws.verifySignature();

            // Do something useful with the result of signature verification
            System.out.println("JWS Signature is valid: " + signatureVerified);
        } catch (Exception e) {
            abortWithUnauthorized(request);
        }
    }

    private boolean isTokenBasedAuthentication(String authorizationHeader) {

        // Check if the Authorization header is valid
        // It must not be null and must be prefixed with "Bearer" plus a whitespace
        // The authentication scheme comparison must be case-insensitive
        return authorizationHeader != null && authorizationHeader.toLowerCase()
                .startsWith(AUTHENTICATION_SCHEME.toLowerCase() + " ");
    }

    private void abortWithUnauthorized(ContainerRequestContext requestContext) {

        // Abort the filter chain with a 401 status code response
        // The WWW-Authenticate header is sent along with the response
        requestContext.abortWith(
                Response.status(Response.Status.UNAUTHORIZED)
                        .header(HttpHeaders.WWW_AUTHENTICATE,
                                AUTHENTICATION_SCHEME + " realm=\"" + "ersres" + "\"")
                        .build());
    }

}
