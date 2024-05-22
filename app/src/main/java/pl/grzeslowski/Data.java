package pl.grzeslowski;

public record Data(String input_ca,
                   String input_clientId,
                   String input_cert,
                   String input_key,
                   String input_endpoint,
                   int input_port,
                   String input_proxyHost,
                   int input_proxyPort,
                   int input_count,
                   String input_topic,
                   String input_message
) {
}
