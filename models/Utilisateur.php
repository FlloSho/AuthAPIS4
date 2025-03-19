<?php
require_once "../config/db.php";

class AuthModel {
    private $pdo;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    public function getUserByUsername($username) {
        $stmt = $this->pdo->prepare("SELECT * FROM Utilisateur WHERE username = ?");
        $stmt->execute([$username]);
        return $stmt->fetch();
    }
}
?>
