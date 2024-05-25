package pl.grzeslowski;

import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.crt.Log;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChallengeNameType;

import java.util.Set;
import java.util.UUID;

@Slf4j
public class App {
    // https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-files.html
    // aws_access_key_id = AKIAIOSFODNN7EXAMPLE 20 chars
    // aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY 13 chars / 7 chars / 18 chars
//    private static final String ACCESS_KEY_XX = "01234567890123456789";
//    private static final String ACCESS_KEY_ID = "eu-central-1_XGRz3CgoY";
//    private static final String SECRET_ACCESS_XXX = "0123456789123/1234567/012345678912345678";
//    private static final String SECRET_ACCESS_KEY = "4pk5efh3v84g5dav43imsv4fbj";

    private static final String CLIENT_ID = "4pk5efh3v84g5dav43imsv4fbj";
    private static final String USER_POOL_ID = "eu-central-1_XGRz3CgoY";
    public static final AuthFlowType AUTH_FLOW_TYPE = AuthFlowType.USER_SRP_AUTH;
    public static final Region REGION = Region.EU_CENTRAL_1;
    private static final Set<ChallengeNameType> SUPPORTED_CHALLENGES = Set.of(ChallengeNameType.PASSWORD_VERIFIER);

    public static void main(String[] args) throws Exception {
//        software.amazon.awssdk.crt.Log.initLoggingToStderr(Log.LogLevel.Trace);
        var level = Log.LogLevel.Trace;
        Log.initLoggingToFile(level, "./issues-586-%s.log".formatted(level.name()));

        if (args.length != 2) {
            throw new SalusException("Username and password are required");
        }
        var username = args[0];
        var password = args[1];
        if (username == null || password == null) {
            throw new SalusException("Username and password are required");
        }
        log.info("Initiating authentication, username: {}, password: {}", username, password);

        // START LOGIN
        var authenticationHelper = new AuthenticationHelper(USER_POOL_ID, CLIENT_ID, REGION.id());
        var accessToken = authenticationHelper.PerformSRPAuthentication(username, password);
        log.info("Authentication result: {}", accessToken);
        var id = authenticationHelper.getId(accessToken);
        log.info("Id: {}", id);
        var credentialsForIdentity = authenticationHelper.getCredentialsForIdentity(accessToken, id.identityId());
        log.info("Credentials: {}", credentialsForIdentity);
        // END LOGIN

        // START MQTT
        log.info("Connecting to MQTT");
        var mqtt = new WsMqtt();
        var connection = mqtt.buildConnection(
                "a24u3z7zzwrtdl",
                REGION.id(),
                "openhab-" + UUID.randomUUID(),
//                credentialsForIdentity.identityId(),
                credentialsForIdentity,
                username,
                password);
//        var connection = mqtt.cognito(
//                "a24u3z7zzwrtdl",
//                REGION.id(),
//                "openhab-"+UUID.randomUUID(),
//                id.identityId(),
//                accessToken.idToken()
//        );
        mqtt.connect(connection);
        // END MQTT

//        log.info("Connecting to HTTP Shadow");
//        var http = new Http();
//        http.shadow("SAU2AG1_GW-001E5E016472-it600ThermHW_AC-001E5E0902049083", credentialsForIdentity);
    }
}
