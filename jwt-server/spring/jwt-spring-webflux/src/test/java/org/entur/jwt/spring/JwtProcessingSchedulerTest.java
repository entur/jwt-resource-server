package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class JwtProcessingSchedulerTest {

    private final ReactiveWebApplicationContextRunner runner = new ReactiveWebApplicationContextRunner().withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, JwtWebFluxSecurityAutoConfiguration.class))
            .withBean(JwkSourceMap.class, () -> new JwkSourceMap<>(Map.of("https://issuer.example", (JWKSource<SecurityContext>) (selector, context) -> List.of()), Map.of()))
            .withBean("applicationScheduler", Scheduler.class, Schedulers::parallel).withPropertyValues("entur.cors.enabled=false", "management.health.jwks.enabled=false");

    @Test
    void shouldDisposeIsolatedSchedulerWhenContextCloses() {
        AtomicReference<Scheduler> scheduler = new AtomicReference<>();
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            Scheduler jwtScheduler = context.getBean("jwtProcessingScheduler", Scheduler.class);
            assertThat(jwtScheduler).isNotSameAs(Schedulers.boundedElastic());
            assertThat(jwtScheduler).isNotSameAs(context.getBean("applicationScheduler", Scheduler.class));
            assertThat(jwtScheduler.isDisposed()).isFalse();
            scheduler.set(jwtScheduler);
        });

        assertThat(scheduler.get().isDisposed()).isTrue();
        assertThat(Schedulers.boundedElastic().isDisposed()).isFalse();
    }

    @Test
    void shouldNotCreateSchedulerWhenJwtIsDisabled() {
        runner.withPropertyValues("entur.jwt.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean("jwtProcessingScheduler");
        });
    }

    @Test
    void shouldAcceptDedicatedSchedulerWithOtherSchedulerBeans() {
        Scheduler scheduler = Schedulers.newBoundedElastic(1, 100, "custom-jwt");
        try {
            runner.withBean("jwtProcessingScheduler", Scheduler.class, () -> scheduler).run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context.getBean("jwtProcessingScheduler", Scheduler.class)).isSameAs(scheduler);
            });
        } finally {
            scheduler.dispose();
        }
    }

    // i.e. an application component which injects its scheduler by type
    static class SchedulerConsumer {

        private final Scheduler scheduler;

        SchedulerConsumer(Scheduler scheduler) {
            this.scheduler = scheduler;
        }
    }

    @Test
    void shouldNotInterfereWithApplicationSchedulerInjection() {
        runner.withBean(SchedulerConsumer.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(SchedulerConsumer.class).scheduler).isSameAs(context.getBean("applicationScheduler", Scheduler.class));
            assertThat(context).hasBean("jwtProcessingScheduler");
        });
    }

    @Test
    void shouldUseDaemonThreads() {
        runner.run(context -> {
            Scheduler jwtScheduler = context.getBean("jwtProcessingScheduler", Scheduler.class);

            // so that a stalled JWK request does not keep the JVM alive
            Thread thread = Mono.fromCallable(Thread::currentThread).subscribeOn(jwtScheduler).block(Duration.ofSeconds(10));
            assertThat(thread.isDaemon()).isTrue();
        });
    }
}
