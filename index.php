<?php
session_start();

// Variable configuration (modify)
$client_id = '';
$client_secret = '';
$redirect_uri = 'http://localhost:8080/';
$metadata_url = 'https://*.okta.com/oauth2/default/.well-known/openid-configuration';

if (isset($_GET['logout'])) {
    unset($_SESSION['username']);
    unset($_SESSION['sub']);
    header('Location: /');
    die();
}

if (isset($_SESSION['sub'])) {
    echo '<p>Logged in as</p>';
    // Sanitizing output to prevent XSS
    echo '<p>' . htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8') . '</p>';
    echo '<p><a href="/?logout">Log Out</a></p>';
    die();
}

$metadata = http($metadata_url);

if (!isset($_GET['code'])) {

    $_SESSION['state'] = bin2hex(random_bytes(5));
    $_SESSION['code_verifier'] = bin2hex(random_bytes(50));
    $code_challenge = base64_urlencode(hash('sha256', $_SESSION['code_verifier'], true));

    $authorize_url = $metadata->authorization_endpoint . '?' . http_build_query([
        'response_type' => 'code',
        'client_id' => $client_id,
        'redirect_uri' => $redirect_uri,
        'state' => $_SESSION['state'],
        'scope' => 'openid profile',
        'code_challenge' => $code_challenge,
        'code_challenge_method' => 'S256',
    ]);

    echo '<p>Not logged in</p>';
    echo '<p><a href="' . $authorize_url . '">Log In</a></p>';

} else {

    if ($_SESSION['state'] != $_GET['state']) {
        die('The authorization server returned an invalid state parameter');
    }

    if (isset($_GET['error'])) {
        die('The authorization server returned an error: ' . htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8'));
    }

    $response = http($metadata->token_endpoint, [
        'grant_type' => 'authorization_code',
        'code' => $_GET['code'],
        'redirect_uri' => $redirect_uri,
        'client_id' => $client_id,
        'client_secret' => $client_secret,
        'code_verifier' => $_SESSION['code_verifier'],
    ]);

    if (!isset($response->access_token)) {
        die('Error obtaining access token');
    }

    $userinfo = http($metadata->userinfo_endpoint, [
        'access_token' => $response->access_token,
    ]);

    if ($userinfo->sub) {
        // Regenerate session ID to prevent session fixation
        session_regenerate_id(true);

        $_SESSION['sub'] = $userinfo->sub;
        $_SESSION['username'] = $userinfo->preferred_username;
        $_SESSION['profile'] = $userinfo;
        header('Location: /');
        die();
    }

}

/**
 * Converts a string to base64 with URL-safe format.
 *
 * This function performs base64 encoding, replacing characters
 * to make it URL-safe and removing trailing '='.
 *
 * @param string $string The string to encode.
 * @return string The base64 URL-safe encoded string.
 */
function base64_urlencode($string) {
    return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
}

/**
 * Performs an HTTP request using cURL.
 *
 * Depending on whether parameters are passed, the function executes
 * a GET or POST request. Also, it closes the cURL resource at the end
 * to prevent memory leaks.
 *
 * @param string $url The URL to send the request to.
 * @param array|bool $params (Optional) Parameters to send via POST; if false, a GET request is used.
 * @return mixed The JSON-decoded response.
 */
function http($url, $params = false) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    if ($params) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    }
    
    $result = curl_exec($ch);
    curl_close($ch); // Closing the resource to free memory
    return json_decode($result);
}
