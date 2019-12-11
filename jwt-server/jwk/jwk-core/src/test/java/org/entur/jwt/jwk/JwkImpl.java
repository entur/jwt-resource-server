package org.entur.jwt.jwk;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

import com.google.common.collect.Maps;

/**
 * Represents a JSON Web Key (JWK) used to verify the signature of JWTs
 */

public class JwkImpl {
    private static final String PUBLIC_KEY_ALGORITHM = "RSA";

    private final String id;
    private final String type;
    private final String algorithm;
    private final String usage;
    private final List<String> operations;
    private final String certificateUrl;
    private final List<String> certificateChain;
    private final String certificateThumbprint;
    private final Map<String, Object> additionalAttributes;

    /**
     * Creates a new Jwk
     *
     * @param id                    kid
     * @param type                  kyt
     * @param algorithm             alg
     * @param usage                 use
     * @param operations            key_ops
     * @param certificateUrl        x5u
     * @param certificateChain      x5c
     * @param certificateThumbprint x5t
     * @param additionalAttributes  additional attributes not part of the standard
     *                              ones
     */

    public JwkImpl(String id, String type, String algorithm, String usage, List<String> operations, String certificateUrl, List<String> certificateChain, String certificateThumbprint, Map<String, Object> additionalAttributes) {
        this.id = id;
        this.type = type;
        this.algorithm = algorithm;
        this.usage = usage;
        this.operations = operations;
        this.certificateUrl = certificateUrl;
        this.certificateChain = certificateChain;
        this.certificateThumbprint = certificateThumbprint;
        this.additionalAttributes = additionalAttributes;
    }

    @SuppressWarnings("unchecked")
    public static JwkImpl fromValues(Map<String, Object> map) throws InvalidSigningKeysException {
        Map<String, Object> values = Maps.newHashMap(map);
        String kid = (String) values.remove("kid");
        String kty = (String) values.remove("kty");
        String alg = (String) values.remove("alg");
        String use = (String) values.remove("use");
        Object keyOps = values.remove("key_ops");
        String x5u = (String) values.remove("x5u");
        List<String> x5c = (List<String>) values.remove("x5c");
        String x5t = (String) values.remove("x5t");
        if (kty == null) {
            throw new InvalidSigningKeysException("Attributes " + map + " are not from a valid jwk");
        }
        return new JwkImpl(kid, kty, alg, use, (List<String>) keyOps, x5u, x5c, x5t, values);
    }

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getUsage() {
        return usage;
    }

    public String getOperations() {
        if (operations == null || operations.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        String delimiter = ",";
        for (String operation : operations) {
            sb.append(operation);
            sb.append(delimiter);
        }
        String ops = sb.toString();
        return ops.substring(0, ops.length() - delimiter.length());
    }

    public List<String> getOperationsAsList() {
        return operations;
    }

    public String getCertificateUrl() {
        return certificateUrl;
    }

    public List<String> getCertificateChain() {
        return certificateChain;
    }

    public String getCertificateThumbprint() {
        return certificateThumbprint;
    }

    public Map<String, Object> getAdditionalAttributes() {
        return additionalAttributes;
    }

    /**
     * Returns a {@link PublicKey} if the {@code 'alg'} is {@code 'RSA'}
     *
     * @return a public key
     * @throws InvalidPublicKeyException if the key cannot be built or the key type
     *                                   is not RSA
     */

    public PublicKey getPublicKey() throws InvalidPublicKeyException {
        if (!PUBLIC_KEY_ALGORITHM.equalsIgnoreCase(type)) {
            throw new InvalidPublicKeyException("The key is not of type RSA", null);
        }
        try {
            KeyFactory kf = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM);
            BigInteger modulus = new BigInteger(1, Base64.decodeBase64(stringValue("n")));
            BigInteger exponent = new BigInteger(1, Base64.decodeBase64(stringValue("e")));
            return kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        } catch (InvalidKeySpecException e) {
            throw new InvalidPublicKeyException("Invalid public key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidPublicKeyException("Invalid algorithm to generate key", e);
        }
    }

    private String stringValue(String key) {
        return (String) additionalAttributes.get(key);
    }

    @Override
    public String toString() {
        return "Jwk [id=" + id + ", type=" + type + ", algorithm=" + algorithm + ", usage=" + usage + ", operations=" + operations + ", certificateUrl=" + certificateUrl + ", certificateChain=" + certificateChain
                + ", certificateThumbprint=" + certificateThumbprint + ", additionalAttributes=" + additionalAttributes + "]";
    }

}
