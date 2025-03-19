<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

/**
 * Génère un JWT à partir des headers, du payload et de la clé secrète fournie
 *
 * @param array $headers
 * @param array $payload
 * @param string $secret
 * @return string
 */
function generate_jwt($headers, $payload, $secret) {
	$headers_encoded = base64url_encode(json_encode($headers));

	$payload_encoded = base64url_encode(json_encode($payload));

	$signature = hash_hmac('SHA256', "$headers_encoded.$payload_encoded", $secret, true);
	$signature_encoded = base64url_encode($signature);

	$jwt = "$headers_encoded.$payload_encoded.$signature_encoded";

	return $jwt;
}

/**
 * Vérifie si un JWT est valide
 *
 * @param string $jwt
 * @param string $secret
 * @return bool
 */
function is_jwt_valid($jwt, $secret): bool
{
	// split the jwt
	$tokenParts = explode('.', $jwt);
	$header = base64url_decode($tokenParts[0]);
	$payload = base64url_decode($tokenParts[1]);
	$signature_provided = $tokenParts[2];

	// check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
	$payload_data = json_decode($payload);
	if (!isset($payload_data->exp)) {
		echo "No expiration time";
		return false;
	}
	$expiration = $payload_data->exp;
	$is_token_expired = ($expiration - time()) < 0;

	// build a signature based on the header and payload using the secret
	$base64_url_header = base64url_encode($header);
	$base64_url_payload = base64url_encode($payload);
	$signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $secret, true);
	$base64_url_signature = base64url_encode($signature);

	// verify it matches the signature provided in the jwt
	$is_signature_valid = ($base64_url_signature === $signature_provided);

	if ($is_token_expired || !$is_signature_valid) {
		echo "Token expired or signature invalid : Sign : $signature_provided / Calculated : $base64_url_signature ";
		var_dump($is_signature_valid);
		echo " ";
		var_dump($is_token_expired);
		return false;
	} else {
		return true;
	}
}

/**
 * Encode une chaîne en base64url
 *
 * @param string $data
 * @return string
 */
function base64url_encode($data) {
	return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Récupère le header Authorization de la requête
 *
 * @return string|null
 */
function get_authorization_header(){
	$headers = null;

	if (isset($_SERVER['Authorization'])) {
		$headers = trim($_SERVER["Authorization"]);
	} else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
		$headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
	} else if (function_exists('apache_request_headers')) {
		$requestHeaders = apache_request_headers();
		// Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
		$requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
		//print_r($requestHeaders);
		if (isset($requestHeaders['Authorization'])) {
			$headers = trim($requestHeaders['Authorization']);
		}
	}

	return $headers;
}

/**
 * Récupère le token JWT dans le header Authorization
 *
 * @return string|null
 */
function get_bearer_token() {
	$headers = get_authorization_header();

	// HEADER: Get the access token from the header
	if (!empty($headers)) {
		if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
			if($matches[1]=='null') //$matches[1] est de type string et peut contenir 'null'
				return null;
			else
				return $matches[1];
		}
	}
	return null;
}

/**
 * Fonction qui envoie une réponse JSON au client.
 *
 * @param int $status_code
 * @param string $status_message
 * @param array|null $data
 */
function deliverResponse($status_code, $status_message, $data = null) {
	http_response_code($status_code);
	echo json_encode([
		"status" => ($status_code >= 200 && $status_code < 300) ? "success" : "error",
		"status_code" => $status_code,
		"status_message" => $status_message,
		"data" => $data
	]);
}

/**
 * Fonction qui récupère le rôle d'un utilisateur à partir d'un JWT
 *
 * @param string $jwt
 * @return string
 */
function get_role_from_jwt($jwt): string
{
	$tokenParts = explode('.', $jwt);
    $payload = base64url_decode($tokenParts[1]);
    $payload_data = json_decode($payload);
    return $payload_data->role;
}

/**
 * Décode une chaîne encodée en base64url
 *
 * @param string $int
 * @return string
 */
function base64url_decode(string $int)
{
	return base64_decode(str_pad(strtr($int, '-_', '+/'), strlen($int) % 4, '=', STR_PAD_RIGHT));
}

/**
 * Valide la connexion avec un JWT
 *
 * @param $jwt
 * @param $secret
 * @return void
 */
function validate_jwt($jwt, $secret) {
    if ($jwt) {
        if (!is_jwt_valid($jwt, $secret)) {
            deliverResponse(401, "Unauthorized", "Token invalide");
            exit();
        }
    } else {
        deliverResponse(401, "Unauthorized", "Token manquant");
        exit();
    }
}
?>
