package org.entur.jwt.jwk.bench;


import java.net.URL;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

import org.entur.jwt.jwk.JwkProvider;
import org.entur.jwt.jwk.UrlJwksProvider;
import org.entur.jwt.jwk.auth0.Auth0JwkProviderBuilder;
import org.entur.jwt.jwk.auth0.Auth0JwkReader;

import com.auth0.jwk.Jwk;

/**
 * Simple multithreaded test-bench for the JWK provider. See that 
 * 
 * - no deadlocks
 * - just a single thread updating
 * 
 * Let this run for a few hours. 
 * 
 */

public class JwkProviderBench extends Thread {

    /**
     * 
     * Simulation of users logging in, needing a token
     * 
     */

    private static final class UserThread extends Thread {

        private boolean close;
        private JwkProvider<Jwk> provider;
        private List<String> keyIds;

        public UserThread(JwkProvider<Jwk> provider, List<String> keyIds) {
            super();
            this.provider = provider;
            this.keyIds = keyIds;
        }

        public void run() {
            Random random = new Random(getName().hashCode());
            try {
                while(!close) {
                    for(String keyId : keyIds) {
                        Jwk jwk = provider.getJwk(keyId);
    
                        if(jwk == null) {
                            throw new RuntimeException();
                        }
                        Thread.sleep(random.nextInt(1000));
                    }
                }
            } catch(InterruptedException e) {
                // do nothing
                System.out.println("Thread " + Thread.currentThread().getName() + " was interrupted");
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println(Thread.currentThread().getName() + " done");
        }

        public void close() {
            close = true;

            interrupt();
        }
    }

    public static final void main(String[] args) throws Exception {
        if(args == null || args.length == 0) {
            System.out.println("Invoke with JWK key URL parameter");
            System.exit(0);
        }
        URL url = new URL(args[0]);
        
        UrlJwksProvider<Jwk> jwksProvider = new UrlJwksProvider<>(url, new Auth0JwkReader(), 15000, 15000);
        
        CounterJwksProvider<Jwk> counterJwksProvider = new CounterJwksProvider<>(jwksProvider);
        
        JwkProvider<Jwk> provider = Auth0JwkProviderBuilder.newBuilder(counterJwksProvider).cached(Duration.ofSeconds(3), Duration.ofSeconds(1)).preemptiveCacheRefresh(Duration.ofSeconds(1), false)
                .rateLimited(10, 1, Duration.ofSeconds(1))
                .preemptiveCacheRefresh(false)
                .build();

        List<String> ids = provider.getJwks(false).stream().map( k -> k.getId()).collect(Collectors.toCollection(ArrayList::new));
        
        int threads = 10000;

        List<UserThread> runners = new ArrayList<>();
        for(int i = 0 ; i < threads; i++) {
            UserThread runner = new UserThread(provider, ids);
            runner.start();

            runners.add(runner);
        }

        System.out.println("Started");

        // if one thread fails, stop all of the thread so that we can read the error message.
        while(true) {
            boolean isAlive = true;
            for(UserThread runner : runners) {
                if(!runner.isAlive()) {
                    isAlive = false;
                }
            }

            if(!isAlive) {
                for(UserThread runner : runners) {
                    runner.close();
                }
                break;
            }
            try {
                Thread.sleep(1000);
                
                System.out.println("Jwks has been fetched " + counterJwksProvider.getCount() + " times");
            } catch (InterruptedException e) {
            }
        }

        System.out.println("Done");
    }

}
