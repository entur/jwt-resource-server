package org.entur.jwt.junit5.extention;

public class AuthorizationServerTestManager {

    // implementation note: Follow pattern from Spring TestContext
    protected final ThreadLocal<AuthorizationServerTestContext> testContextHolder = new ThreadLocal<>();

    /**
     * Get the {@link AuthorizationServerTestContext} managed by this
     * {@code AuthorizationServerTestManager}.
     * 
     * @return the current text context
     */
    public AuthorizationServerTestContext getTestContext() {
        return this.testContextHolder.get();
    }

    public void setTestContext(AuthorizationServerTestContext context) {
        this.testContextHolder.set(context);
    }

    public void removeTestContext() {
        this.testContextHolder.remove();
    }

}
