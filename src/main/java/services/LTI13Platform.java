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

    // TODO: Replace this with the data from the database.

    public static final String AUTHORIZATION_ENDPOINT =
            "https://moodle2.horstmann.com/mod/lti/auth.php";

    public static final String ACCESS_TOKEN_ENDPOINT =
            "https://moodle2.horstmann.com/mod/lti/token.php";

    public static final String JWKS_ENDPOINT =
            "https://moodle2.horstmann.com/mod/lti/certs.php";
}