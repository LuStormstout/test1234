<?php

namespace controllers;

class UserController
{






  

    private $dbConnection;

    public function __construct(mysqli $db) {
        $this->dbConnection = $db;
    }

    public function register($username, $password) {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
        $stmt = $this->dbConnection->prepare($sql);
        if ($stmt === false) {
            throw new \Exception("SQL 预处理失败: " . $this->dbConnection->error);
        }
        $stmt->bind_param("ss", $username, $hashedPassword);
        if (!$stmt->execute()) {
            throw new \Exception("执行 SQL 语句失败: " . $stmt->error);
        }
        if ($stmt->affected_rows > 0) {
            echo "注册成功！";
        } else {
            echo "注册失败，请重试。";
        }
        $stmt->close();
    }

    public function login($username, $password) {
        $sql = "SELECT password FROM users WHERE username = ?";
        $stmt = $this->dbConnection->prepare($sql);
        if ($stmt === false) {
            throw new \Exception("SQL 预处理失败: " . $this->dbConnection->error);
        }
        $stmt->bind_param("s", $username);
        if (!$stmt->execute()) {
            throw new \Exception("执行 SQL 语句失败: " . $stmt->error);
        }
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                echo "登录成功！";
            } else {
                echo "密码错误。";
            }
        } else {
            echo "用户不存在。";
        }
        $stmt->close();
    }
}

