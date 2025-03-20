<?php
global $pdo;
require_once "../config/db.php";
require_once "../controllers/authController.php";

header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

$authController = new AuthController($pdo);
$response = json_decode(file_get_contents("php://input"), true);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($response["username"]) && isset($response["password"])) {
        $result = $authController->login($response["username"], $response["password"]);
        http_response_code($result["status"]);
        echo json_encode($result);
    } else {
        http_response_code(400);
        echo json_encode(["status" => 400, "message" => "Paramètres manquants"]);
    }
} else {
    http_response_code(405);
    echo json_encode(["status" => 405, "message" => "Méthode non autorisée"]);
}
?>