package pl.grzeslowski;

import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.crt.CRT;
import software.amazon.awssdk.crt.CrtResource;
import software.amazon.awssdk.crt.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.crt.mqtt.MqttClientConnectionEvents;
import software.amazon.awssdk.crt.mqtt.QualityOfService;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityResponse;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
public class WsMqtt {
    public MqttClientConnection buildConnection(String prefix,
                                                String region,
                                                String clientId,
                                                GetCredentialsForIdentityResponse credentialsForIdentity,
                                                String username,
                                                String password) {
        try (var builder = AwsIotMqttConnectionBuilder.newMtlsBuilderFromPath(null, null)) {
            MqttClientConnectionEvents callbacks = new MqttClientConnectionEvents() {
                @Override
                public void onConnectionInterrupted(int errorCode) {
                    log.error("Connection interrupted: " + errorCode + ": " + CRT.awsErrorString(errorCode));
                }

                @Override
                public void onConnectionResumed(boolean sessionPresent) {
                    log.error("Connection resumed: " + (sessionPresent ? "existing session" : "clean session"));
                }
            };
            return builder.withEndpoint("%s-ats.iot.%s.amazonaws.com".formatted(prefix, region))
                    .withWebsockets(true)
                    .withConnectionEventCallbacks(callbacks)
                    .withWebsocketSigningRegion(region)
                    .withClientId(clientId)
                    .withWebsocketCredentialsProvider(
                            new StaticCredentialsProvider.StaticCredentialsProviderBuilder()
                                    .withAccessKeyId(credentialsForIdentity.credentials().accessKeyId().getBytes(UTF_8))
                                    .withSecretAccessKey(credentialsForIdentity.credentials().secretKey().getBytes(UTF_8))
                                    .withSessionToken(credentialsForIdentity.credentials().sessionToken().getBytes(UTF_8))
                                    .build())
                    .build();
        }
    }

    public void connect(MqttClientConnection connection) throws ExecutionException, InterruptedException {
        try (connection) {
            CompletableFuture<Boolean> connected = connection.connect();
            boolean sessionPresent = connected.get(); // <--- here!
            log.info("Connected to " + (!sessionPresent ? "new" : "existing") + " session!");
            connection.subscribe("aws/things/+", QualityOfService.AT_LEAST_ONCE);

            log.info("Disconnecting...");
            CompletableFuture<Void> disconnected = connection.disconnect();
            disconnected.get();
            log.info("Disconnected.");
            CrtResource.waitForNoResources();
        }
    }
}
