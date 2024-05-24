package pl.grzeslowski;

import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.crt.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.crt.auth.signing.AwsSigner;
import software.amazon.awssdk.crt.auth.signing.AwsSigningConfig;
import software.amazon.awssdk.crt.http.HttpHeader;
import software.amazon.awssdk.crt.http.HttpRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityResponse;

import java.time.ZoneId;
import java.time.ZonedDateTime;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.eclipse.jetty.http.HttpMethod.GET;

@Slf4j
public class Http {
    private final org.eclipse.jetty.client.HttpClient client;

    public Http() throws Exception {
        client = new org.eclipse.jetty.client.HttpClient();
        client.start();
    }

    public void shadow(
            String thing,
            GetCredentialsForIdentityResponse credentials) throws Exception {
        var path = "https://a24u3z7zzwrtdl-ats.iot.eu-central-1.amazonaws.com/things/%s/shadow".formatted(thing);

        var time = ZonedDateTime.now(ZoneId.of("UTC"));

        HttpRequest httpRequest = new HttpRequest("GET", "/things/%s/shadow".formatted(thing), new HttpHeader[]{
                new HttpHeader("host", "")
        }, null);
        try (var config = new AwsSigningConfig()) {
            config.setRegion("eu-central-1");
            config.setService("iotdevicegateway");
            config.setCredentialsProvider(new StaticCredentialsProvider.StaticCredentialsProviderBuilder()
                    .withAccessKeyId(credentials.credentials().accessKeyId().getBytes(UTF_8))
                    .withSecretAccessKey(credentials.credentials().secretKey().getBytes(UTF_8))
                    .withSessionToken(credentials.credentials().sessionToken().getBytes(UTF_8))
                    .build());
            config.setTime(time.toInstant().toEpochMilli());
            var sign = AwsSigner.sign(httpRequest, config).get();

            var headers1 = sign.getSignedRequest().getHeaders();
            for (var header : headers1) {
                log.info("xyz header {}: {}", header.getName(), header.getValue());
            }

            var signature = new String(sign.getSignature());
            log.info("signature {}", signature);


            var request = client.newRequest(path.formatted(thing));
            request.method(GET);
            request.headers(headers -> {
//                headers.add("Authorization",
//                        "AWS4-HMAC-SHA256 " +
//                                "Credential=ASIAQ2NEK4GTMLAMXVPD/20240524/eu-central-1/iotdevicegateway/aws4_request, " +
////                                "SignedHeaders=accept;host;x-amz-date, " +
//                                "SignedHeaders=host;x-amz-date, " +
//                                "Signature=%s".formatted(signature));
//                var formatter = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
//                headers.add("x-amz-date", time.format(formatter));
//                headers.add("Accept", "application/json");
//                headers.add("x-amz-security-token", credentials.credentials().sessionToken());
                for (var header : headers1) {
                    headers.add(header.getName(), header.getValue());
                }
            });
            var response = request.send();
            var status = response.getStatus();
            log.info("status {}", status);
            log.info("response {}", response.getContentAsString());
            if (status != 200) {
                throw new RuntimeException("%s: %s".formatted(status, response.getContentAsString()));
            }

        } finally {
            client.stop();
        }
//        AwsBasicCredentials awsCredentials = AwsBasicCredentials.create("accessKeyId", "secretAccessKey");
//        AwsCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(awsCredentials);
//
//        HttpRequest httpRequest = HttpRequest.builder()
//                .uri(URI.create(path))
//                .method("GET")
//                .build();
//
//        try (AwsSigningConfig config = AwsSigningConfig.builder()
//                .region(Region.EU_CENTRAL_1)
//                .service("iotdevicegateway")
//                .credentialsProvider(credentialsProvider)
//                .build()) {
//
//
//            HttpRequest signedRequest = AwsSigner.create().sign(httpRequest, config).httpRequest();
//
//            SdkHttpClient httpClient = ApacheHttpClient.builder().build();
//            HttpExecuteRequest executeRequest = HttpExecuteRequest.builder()
//                    .request(signedRequest)
//                    .build();
//
//            try (HttpExecuteResponse response = httpClient.prepareRequest(executeRequest).call()) {
//                System.out.println("Response Code: " + response.httpResponse().statusCode());
//                System.out.println("Response Body: " + response.responseBody().map(r -> r.toString()).orElse("No content"));
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

    }
}
