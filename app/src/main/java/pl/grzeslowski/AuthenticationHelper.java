package pl.grzeslowski;

import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentity.CognitoIdentityClient;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityResponse;
import software.amazon.awssdk.services.cognitoidentity.model.GetIdRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetIdResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Private class for SRP client side math.
 */
class AuthenticationHelper {
    private static final String HEX_N =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                    + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                    + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                    + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                    + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                    + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                    + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                    + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                    + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                    + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                    + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                    + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                    + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                    + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
    private static final BigInteger N = new BigInteger(HEX_N, 16);
    private static final BigInteger g = BigInteger.valueOf(2);
    private static final BigInteger k;
    private static final int EPHEMERAL_KEY_LENGTH = 1024;
    private static final int DERIVED_KEY_SIZE = 16;
    private static final String DERIVED_KEY_INFO = "Caldera Derived Key";
    private static final ThreadLocal<MessageDigest> THREAD_MESSAGE_DIGEST =
            new ThreadLocal<MessageDigest>() {
                @Override
                protected MessageDigest initialValue() {
                    try {
                        return MessageDigest.getInstance("SHA-256");
                    } catch (NoSuchAlgorithmException e) {
                        throw new SecurityException("Exception in authentication", e);
                    }
                }
            };
    private static final SecureRandom SECURE_RANDOM;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG");

            MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
            messageDigest.reset();
            messageDigest.update(N.toByteArray());
            byte[] digest = messageDigest.digest(g.toByteArray());
            k = new BigInteger(1, digest);
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(e.getMessage(), e);
        }
    }

    private BigInteger a;
    private BigInteger A;
    private final String userPoolID;
    private final String clientId;
    //    private final String secretKey;
    private final String region;

    AuthenticationHelper(String userPoolID, String clientid, String region) {
        do {
            a = new BigInteger(EPHEMERAL_KEY_LENGTH, SECURE_RANDOM).mod(N);
            A = g.modPow(a, N);
        } while (A.mod(N).equals(BigInteger.ZERO));

        this.userPoolID = userPoolID;
        this.clientId = clientid;
        this.region = region;
//        this.secretKey = secretKey;
    }

    private BigInteger getA() {
        return A;
    }

    private byte[] getPasswordAuthenticationKey(String userId,
                                                String userPassword,
                                                BigInteger B,
                                                BigInteger salt) throws ShortBufferException, NoSuchAlgorithmException, InvalidKeyException {
        // Authenticate the password
        // u = H(A, B)
        MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
        messageDigest.reset();
        messageDigest.update(A.toByteArray());
        BigInteger u = new BigInteger(1, messageDigest.digest(B.toByteArray()));
        if (u.equals(BigInteger.ZERO)) {
            throw new SecurityException("Hash of A and B cannot be zero");
        }

        // x = H(salt | H(poolName | userId | ":" | password))
        messageDigest.reset();
        messageDigest.update(this.userPoolID.split("_", 2)[1].getBytes(UTF_8));
        messageDigest.update(userId.getBytes(UTF_8));
        messageDigest.update(":".getBytes(UTF_8));
        byte[] userIdHash = messageDigest.digest(userPassword.getBytes(UTF_8));

        messageDigest.reset();
        messageDigest.update(salt.toByteArray());
        BigInteger x = new BigInteger(1, messageDigest.digest(userIdHash));
        BigInteger S = (B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N)).mod(N);

        Hkdf hkdf;
        hkdf = Hkdf.getInstance("HmacSHA256");
        hkdf.init(S.toByteArray(), u.toByteArray());
        return hkdf.deriveKey(DERIVED_KEY_INFO, DERIVED_KEY_SIZE);
    }


    /**
     * Method to orchestrate the SRP Authentication
     *
     * @param username Username for the SRP request
     * @param password Password for the SRP request
     * @return the JWT token if the request is successful else null.
     */
    public AuthenticationResultType PerformSRPAuthentication(String username, String password) throws SalusException, ShortBufferException, NoSuchAlgorithmException, InvalidKeyException {
        InitiateAuthRequest authReq = initiateUserSrpAuthRequest(username);

        AnonymousCredentialsProvider creds = AnonymousCredentialsProvider.create();
        try (CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder()
                .region(Region.of(this.region))
                .credentialsProvider(creds)
                .build()) {

            InitiateAuthResponse authRes = cognitoClient.initiateAuth(authReq);
            if (!authRes.challengeName().equals(ChallengeNameType.PASSWORD_VERIFIER)) {
                throw new SalusException("Unexpected challenge name: " + authRes.challengeName());
            }

            RespondToAuthChallengeRequest challengeRequest = userSrpAuthRequest(authRes, password);
            RespondToAuthChallengeResponse result = cognitoClient.respondToAuthChallenge(challengeRequest);


            return result.authenticationResult();
        }
    }

    /**
     * Initialize the authentication request for the first time.
     *
     * @param username The user for which the authentication request is created.
     * @return the Authentication request.
     */
    private InitiateAuthRequest initiateUserSrpAuthRequest(String username) {

        HashMap<String, String> authParams = new HashMap<String, String>();
        authParams.put("USERNAME", username);
        authParams.put("SRP_A", this.getA().toString(16));

        InitiateAuthRequest authReq = InitiateAuthRequest.builder()
                .authFlow(AuthFlowType.USER_SRP_AUTH)
                .clientId(this.clientId).authParameters(authParams).build();
        return authReq;
    }


    /**
     * Method is used to respond to the Auth challange from the user pool
     *
     * @param challenge The authenticaion challange returned from the cognito user pool
     * @param password  The password to be used to respond to the authentication challenge.
     * @return the Request created for the previous authentication challenge.
     */
    private RespondToAuthChallengeRequest userSrpAuthRequest(InitiateAuthResponse challenge,
                                                             String password) throws ShortBufferException, NoSuchAlgorithmException, InvalidKeyException {
        String userIdForSRP = challenge.challengeParameters().get("USER_ID_FOR_SRP");
        String usernameInternal = challenge.challengeParameters().get("USERNAME");

        BigInteger B = new BigInteger(challenge.challengeParameters().get("SRP_B"), 16);
        if (B.mod(N).equals(BigInteger.ZERO)) {
            throw new SecurityException("SRP error, B cannot be zero");
        }

        BigInteger salt = new BigInteger(challenge.challengeParameters().get("SALT"), 16);
        byte[] key = getPasswordAuthenticationKey(userIdForSRP, password, B, salt);

        Date timestamp = new Date();
        byte[] hmac = null;
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(keySpec);
        mac.update(this.userPoolID.split("_", 2)[1].getBytes(UTF_8));
        mac.update(userIdForSRP.getBytes(UTF_8));
        byte[] secretBlock = Base64.getDecoder().decode(challenge.challengeParameters().get("SECRET_BLOCK"));
        mac.update(secretBlock);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
        simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
        String dateString = simpleDateFormat.format(timestamp);
        byte[] dateBytes = dateString.getBytes(UTF_8);
        hmac = mac.doFinal(dateBytes);

        SimpleDateFormat formatTimestamp = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
        formatTimestamp.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));

        Map<String, String> srpAuthResponses = new HashMap<>();
        srpAuthResponses.put("PASSWORD_CLAIM_SECRET_BLOCK", challenge.challengeParameters().get("SECRET_BLOCK"));
        srpAuthResponses.put("PASSWORD_CLAIM_SIGNATURE", new String(Base64.getEncoder().encode(hmac), UTF_8));
        srpAuthResponses.put("TIMESTAMP", formatTimestamp.format(timestamp));
        srpAuthResponses.put("USERNAME", usernameInternal);

        return RespondToAuthChallengeRequest.builder()
                .challengeName(challenge.challengeName())
                .clientId(clientId)
                .session(challenge.session())
                .challengeResponses(srpAuthResponses).build();
    }

    /**
     * Calculate the secret hash to be sent along with the authentication request.
     *
     * @param userPoolClientId     : The client id of the app.
     * @param userPoolClientSecret : The secret for the userpool client id.
     * @param userName             : The username of the user trying to authenticate.
     * @return Calculated secret hash.
     */
    private String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, String userName) throws NoSuchAlgorithmException, InvalidKeyException {
        final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

        SecretKeySpec signingKey = new SecretKeySpec(
                userPoolClientSecret.getBytes(UTF_8),
                HMAC_SHA256_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
        mac.init(signingKey);
        mac.update(userName.getBytes(UTF_8));
        byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(UTF_8));
        return java.util.Base64.getEncoder().encodeToString(rawHmac);
    }

    public GetIdResponse getId(AuthenticationResultType accessToken) {
        try (var client = CognitoIdentityClient.builder()
                .region(Region.of(region))
                .build()) {
            GetIdRequest getIdRequest = GetIdRequest.builder()
                    .logins(
                            Map.of(
                                    "cognito-idp.eu-central-1.amazonaws.com/eu-central-1_XGRz3CgoY",
                                    accessToken.idToken())
                    )
                    .identityPoolId("eu-central-1:60912c00-287d-413b-a2c9-ece3ccef9230")
                    .build();
            return client.getId(getIdRequest);
        }

    }

    public GetCredentialsForIdentityResponse getCredentialsForIdentity(AuthenticationResultType accessToken, String identityId) {
        try (var client = CognitoIdentityClient.builder()
                .region(Region.of(region))
                .build()) {
            return client.getCredentialsForIdentity(
                    GetCredentialsForIdentityRequest.builder()
                            .identityId(identityId)
                            .logins(
                                    Map.of(
                                            "cognito-idp.eu-central-1.amazonaws.com/eu-central-1_XGRz3CgoY",
                                            accessToken.idToken()))
                            .build());
        }

    }

    /**
     * Internal class for doing the Hkdf calculations.
     */
    final static class Hkdf {
        private static final int MAX_KEY_SIZE = 255;
        private final byte[] EMPTY_ARRAY = new byte[0];
        private final String algorithm;
        private SecretKey prk = null;


        /**
         * @param algorithm REQUIRED: The type of HMAC algorithm to be used.
         */
        private Hkdf(String algorithm) {
            if (!algorithm.startsWith("Hmac")) {
                throw new IllegalArgumentException("Invalid algorithm " + algorithm
                        + ". Hkdf may only be used with Hmac algorithms.");
            } else {
                this.algorithm = algorithm;
            }
        }

        private static Hkdf getInstance(String algorithm) throws NoSuchAlgorithmException {

            return new Hkdf(algorithm);
        }

        /**
         * @param ikm REQUIRED: The input key material.
         */
        public void init(byte[] ikm) throws NoSuchAlgorithmException, InvalidKeyException {
            this.init(ikm, (byte[]) null);
        }

        /**
         * @param ikm  REQUIRED: The input key material.
         * @param salt REQUIRED: Random bytes for salt.
         */
        private void init(byte[] ikm, byte[] salt) throws InvalidKeyException, NoSuchAlgorithmException {
            byte[] realSalt = salt == null ? EMPTY_ARRAY : (byte[]) salt.clone();
            byte[] rawKeyMaterial = EMPTY_ARRAY;

            try {
                final Mac e = Mac.getInstance(this.algorithm);
                if (realSalt.length == 0) {
                    realSalt = new byte[e.getMacLength()];
                    Arrays.fill(realSalt, (byte) 0);
                }

                e.init(new SecretKeySpec(realSalt, this.algorithm));
                rawKeyMaterial = e.doFinal(ikm);
                final SecretKeySpec key = new SecretKeySpec(rawKeyMaterial, this.algorithm);
                Arrays.fill(rawKeyMaterial, (byte) 0);
                this.unsafeInitWithoutKeyExtraction(key);
            } finally {
                Arrays.fill(rawKeyMaterial, (byte) 0);
            }

        }

        /**
         * @param rawKey REQUIRED: Current secret key.
         * @throws InvalidKeyException
         */
        private void unsafeInitWithoutKeyExtraction(SecretKey rawKey) throws InvalidKeyException {
            if (!rawKey.getAlgorithm().equals(this.algorithm)) {
                throw new InvalidKeyException(
                        "Algorithm for the provided key must match the algorithm for this Hkdf. Expected "
                                + this.algorithm + " but found " + rawKey.getAlgorithm());
            } else {
                this.prk = rawKey;
            }
        }

        /**
         * @param info   REQUIRED
         * @param length REQUIRED
         * @return converted bytes.
         */
        private byte[] deriveKey(String info, int length) throws ShortBufferException, NoSuchAlgorithmException, InvalidKeyException {
            return this.deriveKey(info != null ? info.getBytes(UTF_8) : null, length);
        }

        /**
         * @param info   REQUIRED
         * @param length REQUIRED
         * @return converted bytes.
         */
        private byte[] deriveKey(byte[] info, int length) throws ShortBufferException, NoSuchAlgorithmException, InvalidKeyException {
            final byte[] result = new byte[length];
            this.deriveKey(info, length, result, 0);
            return result;
        }

        /**
         * @param info   REQUIRED
         * @param length REQUIRED
         * @param output REQUIRED
         * @param offset REQUIRED
         * @throws ShortBufferException
         */
        private void deriveKey(byte[] info, int length, byte[] output, int offset)
                throws ShortBufferException, NoSuchAlgorithmException, InvalidKeyException {
            this.assertInitialized();
            if (length < 0) {
                throw new IllegalArgumentException("Length must be a non-negative value.");
            } else if (output.length < offset + length) {
                throw new ShortBufferException();
            } else {
                final Mac mac = this.createMac();
                if (length > MAX_KEY_SIZE * mac.getMacLength()) {
                    throw new IllegalArgumentException(
                            "Requested keys may not be longer than 255 times the underlying HMAC length.");
                } else {
                    byte[] t = EMPTY_ARRAY;

                    try {
                        int loc = 0;

                        for (byte i = 1; loc < length; ++i) {
                            mac.update(t);
                            mac.update(info);
                            mac.update(i);
                            t = mac.doFinal();

                            for (int x = 0; x < t.length && loc < length; ++loc) {
                                output[loc] = t[x];
                                ++x;
                            }
                        }
                    } finally {
                        Arrays.fill(t, (byte) 0);
                    }

                }
            }
        }

        /**
         * @return the generates message authentication code.
         */
        private Mac createMac() throws NoSuchAlgorithmException, InvalidKeyException {
            final Mac ex = Mac.getInstance(this.algorithm);
            ex.init(this.prk);
            return ex;
        }

        /**
         * Checks for a valid pseudo-random key.
         */
        private void assertInitialized() {
            if (this.prk == null) {
                throw new IllegalStateException("Hkdf has not been initialized");
            }
        }
    }
}
