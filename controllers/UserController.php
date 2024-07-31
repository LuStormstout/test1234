<?php

namespace controllers;
# namespace 命名空间，用来解决类名冲突的问题

use Exception;
// 引入 Exception 类，用来抛出异常
use models\User;
// use 是 PHP 的一个关键字，用来引入命名空间或者类

# class 关键字用来声明一个类
class UserController
{
    private ?object $dbConnection = null;

    # private 表示这个属性只能在类的内部访问

    # ?object 表示这个属性可以是 null，也可以是 object 类型

    # $a = new Dog();
    # 这样 $a 就是一个 Dog 类的实例，也就是对象

    # PDO 扩展，PHP Data Objects 可以用来连接多种数据库 mysql, sqlite, oracle, mssql
    # MySQLi 扩展，MySQL Improved Extension 是 PHP 5 及以上版本中的一个改进的 MySQL 数据库接口

    # 引入 mysqli 类，要前面加上反斜杠，表示全局空间，否则会在当前命名空间下寻找 mysqli 类
    public function __construct(\mysqli $db)
    {
        $this->dbConnection = $db;
    }

    /**
     * @throws Exception
     */
    public function register($username, $password)
    {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
        $stmt = $this->dbConnection->prepare($sql);
        if ($stmt === false) {
            throw new Exception("SQL 预处理失败: " . $this->dbConnection->error);
        }
        $stmt->bind_param("ss", $username, $hashedPassword);
        if (!$stmt->execute()) {
            throw new Exception("执行 SQL 语句失败: " . $stmt->error);
        }
        if ($stmt->affected_rows > 0) {
            echo "注册成功！";
        } else {
            echo "注册失败，请重试。";
        }
        $stmt->close();
    }

    /**
     * @throws Exception
     */
    public function login($username, $password)
    {
        $sql = "SELECT password FROM users WHERE username = ?";
        $stmt = $this->dbConnection->prepare($sql);
        if ($stmt === false) {
            throw new Exception("SQL 预处理失败: " . $this->dbConnection->error);
        }
        $stmt->bind_param("s", $username);
        if (!$stmt->execute()) {
            throw new Exception("执行 SQL 语句失败: " . $stmt->error);
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

