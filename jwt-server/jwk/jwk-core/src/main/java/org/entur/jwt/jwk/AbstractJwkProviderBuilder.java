package org.entur.jwt.jwk;

/**
 * JwkProvider builder scaffold.
 * 
 * @see <a href="https://www.sitepoint.com/self-types-with-javas-generics/">https://www.sitepoint.com/self-types-with-javas-generics/</a> 
 */

public abstract class AbstractJwkProviderBuilder<T, B extends AbstractJwkProviderBuilder<T, B>> extends AbstractJwksProviderBuilder<T, B>{

	protected JwkFieldExtractor<T> jwkFieldExtractor;
	
    public AbstractJwkProviderBuilder(JwksProvider<T> jwksProvider, JwkFieldExtractor<T> jwkFieldExtractor) {
		super(jwksProvider);
		
		this.jwkFieldExtractor = jwkFieldExtractor;
	}

	/**
     * Creates a {@link JwkProvider}
     *
     * @return a newly created {@link JwkProvider}
     */
    @SuppressWarnings("unchecked")
	public JwkProvider<T> build() {
    	JwksProvider<T> provider = build(jwksProvider);
        if(provider instanceof JwkProvider) {
            return (JwkProvider<T>)provider;
        }
        return new DefaultJwkProvider<T>(provider, jwkFieldExtractor);
        
    }
}
