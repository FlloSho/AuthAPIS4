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
            deliverResponse(401, "Utilisateur non trouvé", null);
        }

        if (!password_verify($password, $user['password'])) {
            deliverResponse(401, "Mot de passe incorrect", null);
        }

        $payload = [
            "user_id" => $user["id"],
            "exp" => time() + 3600
        ];
        $secret = "super_secret_key";
        $jwt = generate_jwt(["alg" => "HS256", "typ" => "JWT"], $payload, $secret);

        deliverResponse(200, "Connexion réussie", ["token" => $jwt]);
    }
}
?>