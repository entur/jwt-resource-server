package org.entur.jwt.jwk;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public abstract class AbstractDelegateProviderTest {

    protected static final String KID = "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg";

    protected JwksProvider<JwkImpl> delegate;
    protected JwkFieldExtractor<JwkImpl> fieldExtractor;

    protected JwkImpl jwk;

    protected List<JwkImpl> jwks;

    @SuppressWarnings("unchecked")
    @BeforeEach
    public void setUp() throws Exception {
        delegate = mock(JwksProvider.class);
        jwk = mock(JwkImpl.class);
        when(jwk.getId()).thenReturn(KID);
        jwks = Arrays.asList(jwk);

        when(delegate.getJwks(false)).thenReturn(jwks);

        fieldExtractor = mock(JwkFieldExtractor.class);
        when(fieldExtractor.getJwkId(any(JwkImpl.class))).then(new Answer<String>() {

            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                JwkImpl jwk = invocation.getArgument(0);

                return jwk.getId();
            }
        });
    }
}
