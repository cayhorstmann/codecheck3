package services;

/**
 * Temporary hard-coded Moodle platform information for the
 * initial LTI 1.3 proof of concept.
 *
 * These values may later be moved into configuration or a database.
 */
public final class LTI13Platform {

    private LTI13Platform() {
        // Prevent this constants-only class from being instantiated.
    }

    public static final String ISSUER =
            "https://moodle.horstmann.com";

    public static final String NAME =
            "horstmann.com Moodle";

    public static final String CLIENT_ID =
            "8EBnFTP5KUoBAfm";

    public static final String AUTHORIZATION_ENDPOINT =
            "https://moodle.horstmann.com/mod/lti/auth.php";

    public static final String ACCESS_TOKEN_ENDPOINT =
            "https://moodle.horstmann.com/mod/lti/token.php";

    public static final String JWKS_ENDPOINT =
            "https://moodle.horstmann.com/mod/lti/certs.php";
}