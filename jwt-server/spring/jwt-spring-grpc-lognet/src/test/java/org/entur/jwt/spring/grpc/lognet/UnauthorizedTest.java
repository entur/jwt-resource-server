package org.entur.jwt.spring.grpc.lognet;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.grpc.test.GreetingRequest;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Semaphore;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test accessing methods with a token which is valid but for some reason still is denied. Check that exceptions are mapped to 
 * 
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class UnauthorizedTest extends AbstractGrpcTest {

    @LocalServerPort
    private int randomServerPort;
    
    @Test 
    public void testOneToOneAccessDeniedException(@AccessToken(audience = "https://my.audience") String header) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub(header).protectedOneToOneAuthenticationException(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
    }
    
    @Test 
    public void testOneToOneStatusRuntimeException(@AccessToken(audience = "https://my.audience") String header) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub(header).protectedOneToOneStatusRuntimeException(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }
    
    @Test 
    public void testOneToManyAccessDeniedException(@AccessToken(audience = "https://my.audience") String header) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            Iterator<GreetingResponse> protectedOneToMany = stub(header).protectedOneToManyAuthenticationException(greetingRequest);
            protectedOneToMany.next();
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
    }
    
    @Test 
    public void testOneToManyStatusRuntimeException(@AccessToken(audience = "https://my.audience") String header) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            Iterator<GreetingResponse> protectedOneToMany = stub(header).protectedOneToManyStatusRuntimeException(greetingRequest);
            protectedOneToMany.next();
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }
    
    @Test 
    public void testManyToOneAccessDeniedException(@AccessToken(audience = "https://my.audience") String header) throws InterruptedException {
        Semaphore semaphore = new Semaphore(1);
        semaphore.acquire();

        final List<GreetingResponse> responses = new ArrayList<>();
        final Throwable[] throwable = new Throwable[1];
        StreamObserver<GreetingResponse> observer = new StreamObserver<GreetingResponse>() {
            @Override
            public void onNext(GreetingResponse response) {
                synchronized(responses) {
                    responses.add(response);
                }
            }

            @Override
            public void onError(Throwable t) {
                throwable[0] = t;
                semaphore.release();
            }

            @Override
            public void onCompleted() {
                semaphore.release();
            }
        };
    
        StreamObserver<GreetingRequest> protectedManyToOne = async(header).protectedManyToOneAuthenticationException(observer);
        protectedManyToOne.onNext(greetingRequest);
        
        semaphore.acquireUninterruptibly();
        
        StatusRuntimeException statusRuntimeException = (StatusRuntimeException)throwable[0];
        
        assertThat(statusRuntimeException.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
    }
    
    @Test 
    public void testManyToOneStatusRuntimeException(@AccessToken(audience = "https://my.audience") String header) throws InterruptedException {
        Semaphore semaphore = new Semaphore(1);
        semaphore.acquire();

        final List<GreetingResponse> responses = new ArrayList<>();
        final Throwable[] throwable = new Throwable[1];
        StreamObserver<GreetingResponse> observer = new StreamObserver<GreetingResponse>() {
            @Override
            public void onNext(GreetingResponse response) {
                synchronized(responses) {
                    responses.add(response);
                }
            }

            @Override
            public void onError(Throwable t) {
                throwable[0] = t;
                semaphore.release();
            }

            @Override
            public void onCompleted() {
                semaphore.release();
            }
        };
    
        StreamObserver<GreetingRequest> protectedManyToOne = async(header).protectedManyToOneStatusRuntimeException(observer);
        protectedManyToOne.onNext(greetingRequest);
        
        semaphore.acquireUninterruptibly();
        
        StatusRuntimeException statusRuntimeException = (StatusRuntimeException)throwable[0];
        
        assertThat(statusRuntimeException.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }    
    
    
    @Test
    public void testManyToManyAccessDeniedException(@AccessToken(audience = "https://my.audience") String header) throws InterruptedException {
        Semaphore semaphore = new Semaphore(1);
        semaphore.acquire();

        final List<GreetingResponse> responses = new ArrayList<>();
        final Throwable[] throwable = new Throwable[1];
        StreamObserver<GreetingResponse> observer = new StreamObserver<GreetingResponse>() {
            @Override
            public void onNext(GreetingResponse response) {
                synchronized(responses) {
                    responses.add(response);
                }
            }

            @Override
            public void onError(Throwable t) {
                throwable[0] = t;
                semaphore.release();
            }

            @Override
            public void onCompleted() {
                semaphore.release();
            }
        };
    
        StreamObserver<GreetingRequest> protectedManyToMany = async(header).protectedManyToManyAuthenticationException(observer);
        protectedManyToMany.onNext(greetingRequest);
        
        semaphore.acquireUninterruptibly();
        
        StatusRuntimeException statusRuntimeException = (StatusRuntimeException)throwable[0];
        
        assertThat(statusRuntimeException.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
    }
    
    @Test
    public void testManyToManyStatusRuntimeException(@AccessToken(audience = "https://my.audience") String header) throws InterruptedException {
        Semaphore semaphore = new Semaphore(1);
        semaphore.acquire();

        final List<GreetingResponse> responses = new ArrayList<>();
        final Throwable[] throwable = new Throwable[1];
        StreamObserver<GreetingResponse> observer = new StreamObserver<GreetingResponse>() {
            @Override
            public void onNext(GreetingResponse response) {
                synchronized(responses) {
                    responses.add(response);
                }
            }

            @Override
            public void onError(Throwable t) {
                throwable[0] = t;
                semaphore.release();
            }

            @Override
            public void onCompleted() {
                semaphore.release();
            }
        };
    
        StreamObserver<GreetingRequest> protectedManyToMany = async(header).protectedManyToManyStatusRuntimeException(observer);
        protectedManyToMany.onNext(greetingRequest);
        
        semaphore.acquireUninterruptibly();
        
        StatusRuntimeException statusRuntimeException = (StatusRuntimeException)throwable[0];
        
        assertThat(statusRuntimeException.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }

}