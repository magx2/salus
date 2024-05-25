package pl.grzeslowski;


import software.amazon.awssdk.crt.CRT;
import software.amazon.awssdk.crt.CrtResource;
import software.amazon.awssdk.crt.auth.credentials.CognitoCredentialsProvider;
import software.amazon.awssdk.crt.http.HttpProxyOptions;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.crt.mqtt.MqttClientConnectionEvents;
import software.amazon.awssdk.crt.mqtt.MqttMessage;
import software.amazon.awssdk.crt.mqtt.QualityOfService;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;


public class Mqtt {
    public void main() throws ExecutionException, InterruptedException {
        Data cmdData = null; /*new Data(
                "",

        );*/

        MqttClientConnectionEvents callbacks = new MqttClientConnectionEvents() {
            @Override
            public void onConnectionInterrupted(int errorCode) {
                if (errorCode != 0) {
                    System.out.println("Connection interrupted: " + errorCode + ": " + CRT.awsErrorString(errorCode));
                }
            }

            @Override
            public void onConnectionResumed(boolean sessionPresent) {
                System.out.println("Connection resumed: " + (sessionPresent ? "existing session" : "clean session"));
            }
        };

        /**
         * Create the MQTT connection from the builder
         */
        AwsIotMqttConnectionBuilder builder = AwsIotMqttConnectionBuilder.newMtlsBuilderFromPath(cmdData.input_cert(), cmdData.input_key());
        if (!Objects.equals(cmdData.input_ca(), "")) {
            builder.withCertificateAuthorityFromPath(null, cmdData.input_ca());
        }
        builder.withConnectionEventCallbacks(callbacks)
                .withClientId(cmdData.input_clientId())
                .withEndpoint(cmdData.input_endpoint())
                .withPort(cmdData.input_port())
                .withCleanSession(true)
                .withProtocolOperationTimeoutMs(60000)
                .withWebsockets(true)
                .withWebsocketCredentialsProvider(new CognitoCredentialsProvider.CognitoCredentialsProviderBuilder()
//                        .
                        .build());
//                .withWebsocketRequestTimeoutMs(60000)
//                .wiWe;
        if (!Objects.equals(cmdData.input_proxyHost(), "") && cmdData.input_proxyPort() > 0) {
            HttpProxyOptions proxyOptions = new HttpProxyOptions();
            proxyOptions.setHost(cmdData.input_proxyHost());
            proxyOptions.setPort(cmdData.input_proxyPort());
            builder.withHttpProxyOptions(proxyOptions);
        }
        MqttClientConnection connection = builder.build();
        builder.close();

        // Connect the MQTT client
        CompletableFuture<Boolean> connected = connection.connect();
        try {
            boolean sessionPresent = connected.get();
            System.out.println("Connected to " + (!sessionPresent ? "new" : "existing") + " session!");
        } catch (Exception ex) {
            throw new RuntimeException("Exception occurred during connect", ex);
        }

        // Subscribe to the topic
        CountDownLatch countDownLatch = new CountDownLatch(cmdData.input_count());
        CompletableFuture<Integer> subscribed = connection.subscribe(cmdData.input_topic(), QualityOfService.AT_LEAST_ONCE, (message) -> {
            String payload = new String(message.getPayload(), StandardCharsets.UTF_8);
            System.out.println("MESSAGE: " + payload);
            countDownLatch.countDown();
        });
        subscribed.get();

        // Publish to the topic
        int count = 0;
        while (count++ < cmdData.input_count()) {
            CompletableFuture<Integer> published = connection.publish(new MqttMessage(cmdData.input_topic(), cmdData.input_message().getBytes(), QualityOfService.AT_LEAST_ONCE, false));
            published.get();
            Thread.sleep(1000);
        }
        countDownLatch.await();

        // Disconnect
        CompletableFuture<Void> disconnected = connection.disconnect();
        disconnected.get();

        // Close the connection now that we are completely done with it.
        connection.close();

        CrtResource.waitForNoResources();
        System.out.println("Complete!");
    }
}
