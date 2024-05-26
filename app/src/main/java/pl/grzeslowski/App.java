package pl.grzeslowski;

import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.crt.Log;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChallengeNameType;

import java.util.List;
import java.util.Set;

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
        var mqtt = new WsMqtt();
        var clientIds = List.of(
                "ASIAQ2NEK4GTDRMMQOFQ",
                "eu-central-1:0d348ae1-a6b1-c9e8-39c4-5d339b3d2afa",
                "ASIAQ2NEK4GTGABE7A2B/20240525/eu-central-1/iotdevicegateway/aws4_request",
                "ASIAQ2NEK4GTGABE7A2B",
                "salus",
                "salus-eu",
                "eu-central-1:60912c00-287d-413b-a2c9-ece3ccef9230",
                "4pk5efh3v84g5dav43imsv4fbj",
                "SA",
                "SAL",
                "0dd0ac86e9813d73206262af5a402db90d6a2fda9b037abecf6d9db10aa2b518",
                "06c45c795babfdd4245dc3ca4c987479",
                "Salus",
                "BDicrWmnPk_EIC6fje4yVDddNylAl-PVqH9fT5ey0YdC2xvPXMbTCWafWJqUZPipbPxRzOOyxBh72s5zPh3Kcjs",
                "BDicrWmnPk",
                "EIC6fje4yVDddNylAl",
                "PVqH9fT5ey0YdC2xvPXMbTCWafWJqUZPipbPxRzOOyxBh72s5zPh3Kcjs",
                "BDicrWmnPk_EIC6fje4yVDddNylAl"
        );
        var ok = false;
        for (var clientId : clientIds) {
            log.info("Connecting to MQTT with clientId: {}", clientId);
//            var connection = mqtt.buildConnection(
//                    "a24u3z7zzwrtdl",
//                    REGION.id(),
//                    clientId,
////                credentialsForIdentity.identityId(),
//                    credentialsForIdentity,
//                    username,
//                    password);
            var connection = mqtt.cognito(
                "a24u3z7zzwrtdl",
                REGION.id(),
                    clientId,
                    id.identityId(),
                    accessToken.idToken()
            );
            try {
                mqtt.connect(connection);
                log.info("CLIENT ID {} WORKS!!!", clientId);
                ok = true;
                break;
            } catch (Exception e) {
                log.error("Error connecting to MQTT {}", e.getLocalizedMessage());
            }
        }
        if (!ok) {
            throw new SalusException("No MQTT client works");
        }
        // END MQTT

//        log.info("Connecting to HTTP Shadow");
//        var http = new Http();
//        http.shadow("SAU2AG1_GW-001E5E016472-it600ThermHW_AC-001E5E0902049083", credentialsForIdentity);
    }
}
