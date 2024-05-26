package pl.grzeslowski;


import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.crt.CRT;
import software.amazon.awssdk.crt.CrtResource;
import software.amazon.awssdk.crt.auth.credentials.CognitoCredentialsProvider;
import software.amazon.awssdk.crt.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.crt.io.ClientBootstrap;
import software.amazon.awssdk.crt.io.ClientTlsContext;
import software.amazon.awssdk.crt.io.TlsContextOptions;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.crt.mqtt.MqttClientConnectionEvents;
import software.amazon.awssdk.crt.mqtt.QualityOfService;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityResponse;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

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
//                    .withWebsocketSigningRegion(region)
//                    .withWebsocketSigningRegion("eu-central-1_XGRz3CgoY")
//                    .withWebsocketSigningRegion("XGRz3CgoY")
                    .withWebsocketSigningRegion("eu-central-1")
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


    public MqttClientConnection cognito(String prefix,
                                        String region,
                                        String clientId,
                                        String cognitoIdentity,
                                        String accessToken) {
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

        AwsIotMqttConnectionBuilder builder = AwsIotMqttConnectionBuilder.newMtlsBuilderFromPath(null, null);
        builder.withConnectionEventCallbacks(callbacks)
                .withClientId(clientId)
                .withEndpoint("%s-ats.iot.%s.amazonaws.com".formatted(prefix, region))
                .withCleanSession(true)
                .withProtocolOperationTimeoutMs(60000);

        builder.withWebsockets(true);
        builder.withWebsocketSigningRegion(region);

        CognitoCredentialsProvider.CognitoCredentialsProviderBuilder cognitoBuilder = new CognitoCredentialsProvider.CognitoCredentialsProviderBuilder();
//        String cognitoEndpoint = "cognito-identity." + region + ".amazonaws.com";
        String cognitoEndpoint = "cognito-idp.eu-central-1.amazonaws.com";
        cognitoBuilder.withEndpoint(cognitoEndpoint)
                .withIdentity(cognitoIdentity)
//                .withLogin(new CognitoCredentialsProvider.CognitoLoginTokenPair(
//                        "cognito-idp.eu-central-1.amazonaws.com/eu-central-1_XGRz3CgoY",
////                        "eu-central-1_XGRz3CgoY",
//                        accessToken)        )
        ;
        cognitoBuilder.withClientBootstrap(ClientBootstrap.getOrCreateStaticDefault());

        TlsContextOptions cognitoTlsContextOptions = TlsContextOptions.createDefaultClient();
        ClientTlsContext cognitoTlsContext = new ClientTlsContext(cognitoTlsContextOptions);
        cognitoTlsContextOptions.close();
        cognitoBuilder.withTlsContext(cognitoTlsContext);

        CognitoCredentialsProvider cognitoCredentials = cognitoBuilder.build();
        builder.withWebsocketCredentialsProvider(cognitoCredentials);

        MqttClientConnection connection = builder.build();
        builder.close();
        cognitoCredentials.close();
        cognitoTlsContext.close();

        return requireNonNull(connection);
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
