<?php

use JetBrains\PhpStorm\NoReturn;

require_once "../models/Utilisateur.php";
require_once "../controllers/jwt_utils.php";

class AuthController
{
    private $authModel;

    public function __construct($pdo)
    {
        $this->authModel = new AuthModel($pdo);
    }

    /**
     * Permet de connecter un utilisateur
     *
     * @param string $username
     * @param string $password
     *
     * @return void
     */
    public function login(string $username, string $password): void
    {
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
            $secret = getenv("SECRET");
            $jwt = generate_jwt(["alg" => "HS256", "typ" => "JWT"], $payload, $secret);

            deliverResponse(200, "Connexion réussie", ["token" => $jwt]);
        }
    }

    public function validateToken(): void
    {
        $jwt = get_bearer_token();
        $secret = $_ENV["SECRET"];
        validate_jwt($jwt, $secret);
    }
}

?>