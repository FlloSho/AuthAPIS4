<?php
require_once "../models/Utilisateur.php";
require_once "../api/jwt_utils.php";

class AuthController {
    private $authModel;

    public function __construct($pdo) {
        $this->authModel = new AuthModel($pdo);
    }

    public function login($username, $password) {
        $user = $this->authModel->getUserByUsername($username);
        if (!$user) {
            deliverResponse(401, "Utilisateur ou mot de passe incorrect", null);
        } elseif (!password_verify($password, $user['password'])) {
            deliverResponse(401, "Utilisateur ou mot de passe incorrect!", null);
        } else {
            $payload = [
                "user_id" => $user["id"],
                "exp" => time() + 3600
            ];
            $secret = "super_secret_key";
            $jwt = generate_jwt(["alg" => "HS256", "typ" => "JWT"], $payload, $secret);

            deliverResponse(200, "Connexion réussie", ["token" => $jwt]);
        }
    }

    public function validate_jwt($jwt, $secret) {
        if (!is_jwt_valid($jwt, $secret)) {
            deliverResponse(401, "Unauthorized", null);
        }
    }
}
?>