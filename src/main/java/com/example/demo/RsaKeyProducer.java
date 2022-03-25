package com.example.demo;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

import java.security.PrivateKey;
import java.security.PublicKey;

public class RsaKeyProducer {

    public RsaKeyProducer() {
    }
    public static void verifyIdToken(String publicKeyText, String idToken)
            throws JoseException, MalformedClaimException {

        // Analiza la información del encabezado (la operación no requiere una clave pública)
        JsonWebSignature jwo = (JsonWebSignature) JsonWebSignature.fromCompactSerialization(idToken);
        String alg = jwo.getHeader("alg");

        // La clave pública se obtiene de la puerta de enlace API basada en kid (cuando se registra la API de autenticación, se configuran keyId y publicKey)
        String kid = jwo.getHeader("kid");

        PublicKey publicKey = new RsaJsonWebKey(JsonUtil.parseJson(publicKeyText)).getPublicKey();

        JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime() // the
                .setAllowedClockSkewInSeconds(30) // allow some leeway in
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
                .setExpectedAudience("Audience") // to whom the JWT is intended
                .setVerificationKey(publicKey) // verify the signature with the public key
                .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, alg))
                .build(); // create the JwtConsumer instance

        try {
            // Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(idToken);
            System.out.println("JWT validation succeeded! " + jwtClaims);
        } catch (InvalidJwtException e) {
            // InvalidJwtException will be thrown, if the JWT failed processing
            // or validation in anyway.
            // Hopefully with meaningful explanations(s) about what went wrong.
            System.out.println("Invalid JWT! " + e);

            // Programmatic access to (some) specific reasons for JWT invalidity
            // is also possible
            // should you want different error handling behavior for certain
            // conditions.

            // Whether or not the JWT has expired being one common reason for
            // invalidity
            if (e.hasExpired()) {
                System.out.println("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
            }

            // Or maybe the audience was invalid
            if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
                System.out.println("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
            }
        }
    }

    // https://bitbucket.org/b_c/jose4j/wiki/JWT%20Examples
    public static String createIdToken(String keyId, String privateKeyText) throws JoseException {


        // claims
        JwtClaims claims = new JwtClaims();
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        // expire time
        NumericDate date = NumericDate.now();
        date.addSeconds (120000); // 1.3 días
        claims.setExpirationTime(date);
        claims.setNotBeforeMinutesInThePast(1);
        claims.setIssuer("Issuer"); // who creates the token and signs it
        claims.setSubject("Subject");
        claims.setAudience("Audience");
        // Añadir parámetros personalizados
        claims.setClaim("UserKey1", "UserVal1");

        // jws
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue(keyId);
        jws.setPayload(claims.toJson());
        PrivateKey privateKey = new RsaJsonWebKey(JsonUtil.parseJson(privateKeyText)).getPrivateKey();
        jws.setKey(privateKey);
        System.out.println("createIdToken::jws=" + jws);

        // idToken
        String idToken = jws.getCompactSerialization();
        System.out.println("createIdToken::idToken=" + idToken);

        return idToken;
    }

}