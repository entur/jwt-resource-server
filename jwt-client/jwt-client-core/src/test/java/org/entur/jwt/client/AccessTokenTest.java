package org.entur.jwt.client;

import org.junit.jupiter.api.Test;

import static com.google.common.truth.Truth.assertThat;

public class AccessTokenTest {

    @Test
    public void testConstructor() {
        AccessToken a = new AccessToken("value", "type", -1L);

        AccessToken b = AccessToken.newInstance("value", "type", -1L);

        assertThat(a).isEqualTo(b);
        assertThat(a.getValue()).isEqualTo("value");
        assertThat(a.getType()).isEqualTo("type");
        assertThat(a.getExpires()).isEqualTo(-1L);
    }
}
