<?php
global $pdo;
require_once "../config/db.php";
require_once "../controllers/authController.php";

// Définir les en-têtes CORS au début
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

// Gérer les requêtes préliminaires OPTIONS pour CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$authController = new AuthController($pdo);
$response = json_decode(file_get_contents("php://input"), true);

switch ($_SERVER['REQUEST_METHOD']) {
    case 'GET':
        $authController->validateToken();
        break;
    case 'POST':
        if (isset($response["username"]) && isset($response["password"])) {
            $authController->login($response["username"], $response["password"]);
        } else {
            deliverResponse(401, "Unauthorized", null);
        }
        break;
    default:
        deliverResponse(405, "Unsupported method", null);
        break;
}
?>