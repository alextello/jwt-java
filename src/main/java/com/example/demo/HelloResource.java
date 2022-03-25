package com.example.demo;



import com.example.demo.service.JWT;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.lang.JoseException;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import java.security.Key;
import java.util.UUID;

@Path("/hello-world")
public class HelloResource {
    @GET
    @Produces("text/plain")
    public String hello() throws JoseException, MalformedClaimException {
        RsaKeyProducer rsaKeyProducer = new RsaKeyProducer();
        // Genera keyId, solo usa uuid de 32 bits.
        String keyId = "MICLAVESECRETA123123";//UUID.randomUUID().toString().replaceAll("-", "");
        System.out.println("keyId=" + keyId);

        // Genera pares de claves públicas y privadas
        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId(keyId);
        jwk.setAlgorithm(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

        //Llave pública
        String publicKeyText = jwk.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        System.out.println("publicKeyText====="+publicKeyText);

        //Llave privada
        String privateKeyText = jwk.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        System.out.println("privateKeyText====="+privateKeyText);

        // Firmar por clave privada para generar token
        String idToken = rsaKeyProducer.createIdToken(keyId, privateKeyText);
        rsaKeyProducer.verifyIdToken(publicKeyText, idToken);

        return idToken;
    }

    @GET()
    @Path("/notarios")
    @Produces("text/plain")
    public String notarios() throws JoseException, MalformedClaimException {
        RsaKeyProducer rsaKeyProducer = new RsaKeyProducer();
        // Genera keyId, solo usa uuid de 32 bits.
        String keyId = "MICLAVESECRETA123123";//UUID.randomUUID().toString().replaceAll("-", "");
        System.out.println("keyId=" + keyId);

        // Genera pares de claves públicas y privadas
        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId(keyId);
        jwk.setAlgorithm(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

        //Llave pública
        String publicKeyText = jwk.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        System.out.println("publicKeyText====="+publicKeyText);

        //Llave privada
        String privateKeyText = jwk.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        System.out.println("privateKeyText====="+privateKeyText);

        // Firmar por clave privada para generar token
        String idToken = rsaKeyProducer.createIdToken(keyId, privateKeyText);
        rsaKeyProducer.verifyIdToken(publicKeyText, idToken);

        return idToken;
    }
}