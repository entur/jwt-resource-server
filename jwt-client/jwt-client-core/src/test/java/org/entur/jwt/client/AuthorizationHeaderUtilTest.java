package org.entur.jwt.client;

import org.junit.jupiter.api.Test;

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
    public void shouldUseStandardBase64Alphabet() {
        // the standard encoding of these credentials contains a '/', which the url-safe alphabet would replace with '_'
        String header = AuthorizationHeaderUtil.createHeader("my-client", "s3cr3t>?~");

        assertThat(header).isEqualTo("Basic bXktY2xpZW50OnMzY3IzdD4/fg==");

        String decoded = new String(Base64.getDecoder().decode(header.substring("Basic ".length())), StandardCharsets.UTF_8);
        assertThat(decoded).isEqualTo("my-client:s3cr3t>?~");
    }
}
