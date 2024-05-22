package pl.grzeslowski;

import java.io.Serial;

@SuppressWarnings("SerializableHasSerializationMethods")
public class SalusException extends Exception{
    @Serial
    private static final long serialVersionUID = 1L;

    public SalusException() {
    }

    public SalusException(String message) {
        super(message);
    }

    public SalusException(String message, Throwable cause) {
        super(message, cause);
    }

    public SalusException(Throwable cause) {
        super(cause);
    }

    public SalusException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
