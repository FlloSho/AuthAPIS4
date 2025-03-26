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
        $authController->login($response["username"], $response["password"]);
    } else {
        deliverResponse(401, "Unauthorized", null);
    }
} else {
    deliverResponse(405, "Unsupported method", null);
}
?>