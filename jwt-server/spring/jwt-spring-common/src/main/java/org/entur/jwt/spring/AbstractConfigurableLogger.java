package org.entur.jwt.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import static org.slf4j.event.EventConstants.DEBUG_INT;
import static org.slf4j.event.EventConstants.ERROR_INT;
import static org.slf4j.event.EventConstants.INFO_INT;
import static org.slf4j.event.EventConstants.TRACE_INT;
import static org.slf4j.event.EventConstants.WARN_INT;

public abstract class AbstractConfigurableLogger {

    protected BooleanSupplier enabled;
    protected BiConsumer<String, Throwable> logger;

    public AbstractConfigurableLogger(String loggerName, String levelName, boolean stackTrace) {
        this(LoggerFactory.getLogger(loggerName), parseLevel(levelName), stackTrace);
    }

    public AbstractConfigurableLogger(Logger logger, Level level, boolean stackTrace) {
        this.enabled = logEnabledToBooleanSupplier(level, logger);
        if(stackTrace) {
            this.logger = loggerToBiConsumer(level, logger);
        } else {
            Consumer<String> stringConsumer = loggerToConsumer(level, logger);
            this.logger = (s, t) -> stringConsumer.accept(s);
        }
    }

    protected BooleanSupplier logEnabledToBooleanSupplier(Level level, Logger logger) {
        int levelInt = level.toInt();
        switch (levelInt) {
            case (TRACE_INT):
                return logger::isTraceEnabled;
            case (DEBUG_INT):
                return logger::isDebugEnabled;
            case (INFO_INT):
                return logger::isInfoEnabled;
            case (WARN_INT):
                return logger::isWarnEnabled;
            case (ERROR_INT):
                return logger::isErrorEnabled;
            default:
                throw new IllegalStateException("Level [" + level + "] not recognized.");
        }
    }

    protected BiConsumer<String, Throwable> loggerToBiConsumer(Level level, Logger logger) {

        int levelInt = level.toInt();
        switch (levelInt) {
            case (TRACE_INT):
                return logger::trace;
            case (DEBUG_INT):
                return  logger::debug;
            case (INFO_INT):
                return logger::info;
            case (WARN_INT):
                return  logger::warn;
            case (ERROR_INT):
                return logger::error;
            default:
                throw new IllegalStateException("Level [" + level + "] not recognized.");
        }
    }

    protected Consumer<String> loggerToConsumer(Level level, Logger logger) {

        int levelInt = level.toInt();
        switch (levelInt) {
            case (TRACE_INT):
                return logger::trace;
            case (DEBUG_INT):
                return  logger::debug;
            case (INFO_INT):
                return logger::info;
            case (WARN_INT):
                return  logger::warn;
            case (ERROR_INT):
                return logger::error;
            default:
                throw new IllegalStateException("Level [" + level + "] not recognized.");
        }
    }


    public static Level parseLevel(String loggerLevel) {
        switch (loggerLevel.toLowerCase()) {
            case "trace": return Level.TRACE;
            case "debug": return Level.DEBUG;
            case "info": return Level.INFO;
            case "warn": return Level.WARN;
            case "error": return Level.ERROR;
            default : {
                throw new IllegalStateException("Unknown logger level " + loggerLevel);
            }
        }
    }
}
