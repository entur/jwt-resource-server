package org.entur.jwt.spring.grpc.exception;


import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;

import javax.annotation.Nullable;

import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.SettableFuture;

import io.grpc.ForwardingServerCallListener.SimpleForwardingServerCallListener;
import io.grpc.Attributes;
import io.grpc.ForwardingServerCall;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCall.Listener;
import io.grpc.internal.SerializingExecutor;
import io.grpc.util.TransmitStatusRuntimeExceptionInterceptor;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;

/**
 * 
 * Based on {@linkplain TransmitStatusRuntimeExceptionInterceptor}. <br>
 * This seems like quite a lot of wiring, but at least this class allows for a single
 * overhead cost (by translating more than just {@linkplain StatusRuntimeException}).<br>
 *
 */

public class GrpcRuntimeExceptionTranslationInterceptor implements ServerInterceptor {

    private final List<ServerCallRuntimeExceptionTranslator> translators;

    public GrpcRuntimeExceptionTranslationInterceptor(ServerCallRuntimeExceptionTranslator ... translators) {
        this(Arrays.asList(translators));
    }

    public GrpcRuntimeExceptionTranslationInterceptor(List<ServerCallRuntimeExceptionTranslator> translators) {
        this.translators = translators;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call,
            Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {
        try {
            final ServerCall<ReqT, RespT> serverCall = new SerializingServerCall<>(call);
            ServerCall.Listener<ReqT> listener = next.startCall(serverCall, headers);
            return new SimpleForwardingServerCallListener<ReqT>(listener) {

                @Override
                public void onMessage(ReqT message) {
                    try {
                        super.onMessage(message);
                    } catch (RuntimeException e) {
                        translateToStatus(e, call);
                    }
                }

                @Override
                public void onHalfClose() {
                    try {
                        super.onHalfClose();
                    } catch (RuntimeException e) {
                        translateToStatus(e, call);
                    }
                }

                @Override
                public void onCancel() {
                    try {
                        super.onCancel();
                    } catch (RuntimeException e) {
                        translateToStatus(e, call);
                    }                    
                }

                @Override
                public void onComplete() {
                    try {
                        super.onComplete();
                    } catch (RuntimeException e) {
                        translateToStatus(e, call);
                    }
                }

                @Override
                public void onReady() {
                    try {
                        super.onReady();
                    } catch (RuntimeException e) {
                        translateToStatus(e, call);
                    }
                }

            };
        } catch(RuntimeException e) { // i.e. by startCall
            translateToStatus(e, call);
            return new Listener<ReqT>() {};
        }
    }

    private <ReqT, RespT> void translateToStatus(RuntimeException e, ServerCall<ReqT, RespT> call) {
        for (ServerCallRuntimeExceptionTranslator serverCallRuntimeExceptionTranslator : translators) {
            if(serverCallRuntimeExceptionTranslator.close(call, e)) {
                return;
            }
        }
        throw e;
    }


    /**
     * A {@link ServerCall} that wraps around a non thread safe delegate and provides thread safe
     * access by serializing everything on an executor.
     */
    private static class SerializingServerCall<ReqT, RespT> extends
    ForwardingServerCall.SimpleForwardingServerCall<ReqT, RespT> {
        private static final String ERROR_MSG = "Encountered error during serialized access";
        private final SerializingExecutor serializingExecutor =
                new SerializingExecutor(MoreExecutors.directExecutor());
        private boolean closeCalled = false;

        SerializingServerCall(ServerCall<ReqT, RespT> delegate) {
            super(delegate);
        }

        @Override
        public void sendMessage(final RespT message) {
            serializingExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    SerializingServerCall.super.sendMessage(message);
                }
            });
        }

        @Override
        public void request(final int numMessages) {
            serializingExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    SerializingServerCall.super.request(numMessages);
                }
            });
        }

        @Override
        public void sendHeaders(final Metadata headers) {
            serializingExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    SerializingServerCall.super.sendHeaders(headers);
                }
            });
        }

        @Override
        public void close(final Status status, final Metadata trailers) {
            serializingExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    if (!closeCalled) {
                        closeCalled = true;

                        SerializingServerCall.super.close(status, trailers);
                    }
                }
            });
        }

        @Override
        public boolean isReady() {
            final SettableFuture<Boolean> retVal = SettableFuture.create();
            serializingExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    retVal.set(SerializingServerCall.super.isReady());
                }
            });
            try {
                return retVal.get();
            } catch (InterruptedException e) {
                throw new RuntimeException(ERROR_MSG, e);
            } catch (ExecutionException e) {
                throw new RuntimeException(ERROR_MSG, e);
            }
        }

        @Override
        public boolean isCancelled() {
            final SettableFuture<Boolean> retVal = SettableFuture.create();
            serializingExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    retVal.set(SerializingServerCall.super.isCancelled());
                }
            });
            try {
                return retVal.get();
            } catch (InterruptedException e) {
                throw new RuntimeException(ERROR_MSG, e);
            } catch (ExecutionException e) {
                throw new RuntimeException(ERROR_MSG, e);
            }
        }

        @Override
        public void setMessageCompression(final boolean enabled) {
            serializingExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    SerializingServerCall.super.setMessageCompression(enabled);
                }
            });
        }

        @Override
        public void setCompression(final String compressor) {
            serializingExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    SerializingServerCall.super.setCompression(compressor);
                }
            });
        }

        @Override
        public Attributes getAttributes() {
            final SettableFuture<Attributes> retVal = SettableFuture.create();
            serializingExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    retVal.set(SerializingServerCall.super.getAttributes());
                }
            });
            try {
                return retVal.get();
            } catch (InterruptedException e) {
                throw new RuntimeException(ERROR_MSG, e);
            } catch (ExecutionException e) {
                throw new RuntimeException(ERROR_MSG, e);
            }
        }

        @Nullable
        @Override
        public String getAuthority() {
            final SettableFuture<String> retVal = SettableFuture.create();
            serializingExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    retVal.set(SerializingServerCall.super.getAuthority());
                }
            });
            try {
                return retVal.get();
            } catch (InterruptedException e) {
                throw new RuntimeException(ERROR_MSG, e);
            } catch (ExecutionException e) {
                throw new RuntimeException(ERROR_MSG, e);
            }
        }
    }    

}