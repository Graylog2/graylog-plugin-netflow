package org.graylog.plugins.netflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class UpdateTemplates {
    private static final String DEFAULT_URL = "https://raw.githubusercontent.com/logstash-plugins/logstash-codec-netflow/656e5fefbfe55d26416242c8cdeb8769a069724a/lib/logstash/codecs/netflow/netflow.yaml";

    public static void main(String[] args) throws Exception {
        final String gitHubUrl = System.getProperty("url", DEFAULT_URL);
        final String fileName = System.getProperty("filename", "netflow9.csv");
        final boolean verbose = Boolean.getBoolean("verbose");

        final ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        final JsonNode node = mapper.readValue(new URL(gitHubUrl), JsonNode.class);

        assertThat(node.isObject()).isTrue();

        try (FileOutputStream fileOutputStream = new FileOutputStream(fileName);
             OutputStreamWriter writer = new OutputStreamWriter(fileOutputStream, StandardCharsets.UTF_8)) {

            final Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                final Map.Entry<String, JsonNode> field = fields.next();
                final JsonNode value = field.getValue();
                if (!value.isArray()) {
                    System.err.println("Skipping incomplete record: " + field);
                    continue;
                }

                if (value.size() != 2) {
                    System.err.println("Skipping incomplete record: " + field);
                    continue;
                }

                final JsonNode typeNode = value.get(0);
                final int length;
                if (typeNode.isTextual()) {
                    length = typeToByteLength(typeNode.asText());
                } else if (typeNode.isInt()) {
                    length = typeNode.asInt();
                } else {
                    System.err.println("Skipping invalid record type: " + field);
                    continue;
                }

                final JsonNode nameNode = value.get(1);
                if (!nameNode.isTextual()) {
                    System.err.println("Skipping invalid record type: " + field);
                    continue;
                }

                final String symbol = nameNode.asText();
                final String name = rubySymbolToString(symbol);
                final String id = field.getKey();

                writer.write(id + "," + name + "," + length + "\n");

                if (verbose) {
                    System.out.println(id + "," + name + "," + length);
                }
            }
        }
    }

    private static String rubySymbolToString(String symbol) {
        if (symbol.charAt(0) == ':') {
            return symbol.substring(1);
        } else {
            return symbol;
        }
    }

    private static int typeToByteLength(String type) {
        switch (type) {
            case ":uint8":
                return 1;
            case ":uint16":
                return 2;
            case ":uint32":
                return 4;
            case ":uint64":
                return 8;
            case ":ip4_addr":
                return 4;
            case ":ip6_addr":
                return 16;
            case ":mac_addr":
                return 6;
            case ":string":
                return 0;
            default:
                System.err.println("Unknown type: " + type);
                return 0;
        }
    }
}
