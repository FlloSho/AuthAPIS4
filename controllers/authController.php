<?php
require_once "../models/authModel.php";
require_once "../api/jwt_utils.php";

class AuthController {
    private $authModel;

    public function __construct($pdo) {
        $this->authModel = new AuthModel($pdo);
    }

    public function login($username, $password) {
        $user = $this->authModel->getUserByUsername($username);

        if (!$user) {
            return ["status" => 404, "message" => "Utilisateur non trouvé"];
        }

        if (!password_verify($password, $user['password'])) {
            return ["status" => 401, "message" => "Mot de passe incorrect"];
        }

        $payload = [
            "user_id" => $user["id"],
            "role" => $user["role"],
            "exp" => time() + 3600
        ];
        $secret = "super_secret_key";
        $jwt = generate_jwt(["alg" => "HS256", "typ" => "JWT"], $payload, $secret);

        return ["status" => 200, "message" => "Connexion réussie", "token" => $jwt];
    }
}
?>

