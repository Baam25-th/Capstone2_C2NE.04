<?php
    include "mongoExt.php";

    $uri = "mongodb+srv://crackervn029:lethithuy1011@cluster0.wnmnk0w.mongodb.net/?retryWrites=true&w=majority";

    $mongoose = new MongoDBConnectExt();

    $connectMongoDB = $mongoose->connectMongoDB($uri);

    if(isset($_POST['btnRegister'])){
        $email = $_POST['email'];
        $password = $_POST['password'];
        $confirm_pass = $_POST['confirm_password'];
        if($mongoose->IsNullOrEmptyString($email) || $mongoose->IsNullOrEmptyString($password) || $mongoose->IsNullOrEmptyString($confirm_pass)){
            echo '<script>alert("Vui lòng nhập điền đầy đủ thông tin đăng ký")</script>';
        }
        else{
            if($password == $confirm_pass){
                if($mongoose->checkUserInDB($connectMongoDB, "WAPTT", "Users", $email)){
                    $mongoose->insertUsers($connectMongoDB, "WAPTT", "Users", $email, $password);                   
                    echo '<script>alert("Đăng ký thành công. Tự động chuyển đến trang đăng nhập")</script>';
                    echo "<script>window.location = 'sign_in.php';</script>";
                }
                else
                    echo '<script>alert("Email đăng ký đã tồn tại")</script>';
            }
            else
                echo '<script>alert("Nhập lại mật khẩu sai")</script>';
        }
    }


?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="index.css">
    <title>WAPTT Sign Up</title>
</head>
<body>
    <section>
        <div class="form-box">
            <div class="form-value">
                <form onsubmit="signup()" action="sign_up.php" method="POST">
                    <h2>Sign Up
                    </h2>
                    <div class="inputbox">
                        <ion-icon name="mail-outline"></ion-icon>
                        <input type="email" name="email" id="email_username">
                        <label for="">Email</label>
                    </div>
                    <div class="inputbox">
                        <ion-icon name="lock-closed-outline"></ion-icon>
                        <input type="password" name="password" id="password">
                        <label for="">Password</label>
                    </div>
                    <div class="inputbox">
                        <ion-icon name="lock-closed-outline"></ion-icon>
                        <input type="password" name="confirm_password" id="cofirm_password">
                        <label for="">Confirm Password</label>
                    </div>
                    <button type="submit" name="btnRegister">Sign Up</button>
                    <div class="register">
                        <p>Do you already have an account?&nbsp<a href="sign_in.php">Login Now</a></p>
                    </div>
                </form>
            </div>
        </div>
    </section>
    <!--<script type="module" src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.esm.js"></script>
    <script nomodule src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.js"></script>
    <script src="./main.js"></script>-->
</body>
</html>