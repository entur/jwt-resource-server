package org.entur.jwt.spring.grpc;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Semaphore;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.grpc.test.GreetingRequest;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;

/**
 * Test accessing methods with a token which is valid but for some reason still is denied
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
            stub(header).protectedOneToOne(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
    }
    
    @Test 
    public void testOneToManyAccessDeniedException(@AccessToken(audience = "https://my.audience") String header) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            Iterator<GreetingResponse> protectedOneToMany = stub(header).protectedOneToMany(greetingRequest);
            protectedOneToMany.next();
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
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
    
		StreamObserver<GreetingRequest> protectedManyToOne = async(header).protectedManyToOne(observer);
		protectedManyToOne.onNext(greetingRequest);
		
		semaphore.acquireUninterruptibly();
		
		StatusRuntimeException statusRuntimeException = (StatusRuntimeException)throwable[0];
		
        assertThat(statusRuntimeException.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
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
    
		StreamObserver<GreetingRequest> protectedManyToMany = async(header).protectedManyToMany(observer);
		protectedManyToMany.onNext(greetingRequest);
		
		semaphore.acquireUninterruptibly();
		
		StatusRuntimeException statusRuntimeException = (StatusRuntimeException)throwable[0];
		
        assertThat(statusRuntimeException.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
    }

}