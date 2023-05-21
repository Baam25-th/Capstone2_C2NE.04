<?php
    include "mongoExt.php";

    session_start();

    if(isset($_SESSION['email'])){
        header("Location: main.php");
      }

    $uri = "mongodb+srv://crackervn029:lethithuy1011@cluster0.wnmnk0w.mongodb.net/?retryWrites=true&w=majority";

    $mongoose = new MongoDBConnectExt();

    $connectMongoDB = $mongoose->connectMongoDB($uri);


    if(isset($_POST['btnLogin'])){
        $email = $_POST['email'];
        $password = $_POST['password'];
        if($mongoose->IsNullOrEmptyString($email) || $mongoose->IsNullOrEmptyString($password))
            echo '<script>alert("Vui lòng nhập đầy đủ thông tin đăng nhập")</script>';
        else{
            $tempData = $mongoose->findUserInDB($connectMongoDB, "WAPTT", "Users", $email);
            if($tempData[0]['email'] == $email && $tempData[0]['password'] == $password){
                echo '<script>alert("Đăng nhập thành công")</script>';
                $_SESSION['email'] = $email;
                header("Location: main.php");
            }               
            else
                echo '<script>alert("Email hoặc mật khẩu sai. Vui lòng thử lại")</script>';
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
    <title>WAPTT</title>
</head>
<body>
    <section>
        <div class="form-box">
            <div class="form-value">
                <form action="sign_in.php" method="POST">
                    <h2>Sign In

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
                    <!--<div class="forget">
                        <label for=""><input type="checkbox">Remember Me <a href="">Forget Password</a></label>
                        
                    </div>-->
                    <button type="submit" name="btnLogin">Sign In</button>
                    <div class="register">
                        <p>Don't have a account?&nbsp<a href="sign_up.php">Register</a></p>
                    </div>
                </form>
            </div>
        </div>
    </section>
    <script type="module" src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.esm.js"></script>
    <script nomodule src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.js"></script>
    <script src="./main.js"></script>
</body>
</html>