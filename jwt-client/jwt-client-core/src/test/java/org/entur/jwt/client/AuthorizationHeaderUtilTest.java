package org.entur.jwt.client;

import org.junit.jupiter.api.Test;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.google.common.truth.Truth.assertThat;

public class AuthorizationHeaderUtilTest {

    @Test
    public void shouldCreateBasicAuthorizationHeader() {
        String header = AuthorizationHeaderUtil.createHeader("myClientId", "mySecret");

        assertThat(header).isEqualTo("Basic bXlDbGllbnRJZDpteVNlY3JldA==");
    }

    @Test
    public void shouldEncodeLikeSpringSecurity() {
        // expected values created by Spring Security 7.1.2 (client_secret_basic)
        assertThat(AuthorizationHeaderUtil.createHeader("my-client", "s3cr3t>?~")).isEqualTo("Basic bXktY2xpZW50OnMzY3IzdCUzRSUzRiU3RQ==");
        assertThat(AuthorizationHeaderUtil.createHeader("client", "p+ss/w0rd==")).isEqualTo("Basic Y2xpZW50OnAlMkJzcyUyRncwcmQlM0QlM0Q=");
        assertThat(AuthorizationHeaderUtil.createHeader("klient", "hemmelig æøå%")).isEqualTo("Basic a2xpZW50OmhlbW1lbGlnKyVDMyVBNiVDMyVCOCVDMyVBNSUyNQ==");
    }

    @Test
    public void shouldBeDecodedToTheOriginalCredentials() {
        String[][] credentials = { { "my-client", "s3cr3t>?~" }, { "client", "p+ss/w0rd==" }, { "klient", "hemmelig æøå%" }, { "client:with:colons", "secret:with:colons" } };

        for (String[] c : credentials) {
            String header = AuthorizationHeaderUtil.createHeader(c[0], c[1]);

            // like the authorization server (i.e. Keycloak): Base64 decode, split at the first colon, then url-decode
            String decoded = new String(Base64.getDecoder().decode(header.substring("Basic ".length())), StandardCharsets.UTF_8);
            int index = decoded.indexOf(':');

            assertThat(URLDecoder.decode(decoded.substring(0, index), StandardCharsets.UTF_8)).isEqualTo(c[0]);
            assertThat(URLDecoder.decode(decoded.substring(index + 1), StandardCharsets.UTF_8)).isEqualTo(c[1]);
        }
    }
}
