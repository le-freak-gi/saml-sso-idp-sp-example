package example.saml.idp;

import java.util.Arrays;
import java.util.List;

public class SamlAttribute {

    private final String name;
    private final List<String> values;

    public SamlAttribute(String name, List<String> values) {
        this.name = name;
        this.values = values;
    }

    public SamlAttribute(String name, String value) {
        this.name = name;
        this.values = Arrays.asList(value);
    }

    public String getName() {
        return name;
    }

    public List<String> getValues() {
        return values;
    }

    public String getValue() {
        return String.join(", ", values);
    }

    @Override
    public String toString() {
        return "SAMLAttribute{" + "name='" + name + '\'' + ", values=" + values + '}';
    }
}
