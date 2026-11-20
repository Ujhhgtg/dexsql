package fixtures;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

public class FieldAnnotations {
    @Retention(RetentionPolicy.RUNTIME)
    public @interface Serialized {
        String value();
    }

    @Serialized("message") private String text;
    @Serialized("other") private String other;

    public String read() { return text; }
    public String readOther() { return other; }
    public void write(String value) { text = value; }
}
