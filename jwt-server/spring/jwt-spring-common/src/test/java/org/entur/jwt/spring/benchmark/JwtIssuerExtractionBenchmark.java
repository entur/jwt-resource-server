package org.entur.jwt.spring.benchmark;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.entur.jwt.spring.JwtIssuerBase64Matcher;
import org.entur.jwt.spring.JwtIssuerClaimExtractor;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
public class JwtIssuerExtractionBenchmark {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private String token;
    private String payloadSegment;
    private JwtIssuerBase64Matcher matcher;

    @Setup(Level.Trial)
    public void setup() {
        String payload = "{\"sub\":\"abc\",\"aud\":\"x\",\"iss\":\"https://issuer-2.example\",\"scope\":\"read\"}";
        token = token(payload);
        payloadSegment = token.split("\\.")[1];
        matcher = new JwtIssuerBase64Matcher(List.of("https://issuer-1.example", "https://issuer-2.example"));
    }

    @Benchmark
    public String customExtractor() {
        return JwtIssuerClaimExtractor.extractIssuer(token);
    }

    @Benchmark
    public String nimbusClaimsSet() throws Exception {
        return SignedJWT.parse(token).getJWTClaimsSet().getIssuer();
    }

    @Benchmark
    public String jacksonPayloadParsing() throws Exception {
        byte[] payload = Base64.getUrlDecoder().decode(payloadSegment);
        JsonNode jsonNode = OBJECT_MAPPER.readTree(payload);
        JsonNode issuer = jsonNode.get("iss");
        return issuer != null ? issuer.asText() : null;
    }

    @Benchmark
    public String base64BodyThreeEncodingSearch() {
        return matcher.matchIssuerFromToken(token);
    }

    private static String token(String payloadJson) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".sig";
    }
}
