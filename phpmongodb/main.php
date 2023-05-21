<?php
  include "mongoExt.php";
  use voku\helper\AntiXSS;
  
  date_default_timezone_set("Asia/Ho_Chi_Minh");
  ini_set('max_execution_time', 600); // 10 minutes

  $antiXss = new AntiXSS();
  $uri = "mongodb+srv://crackervn029:lethithuy1011@cluster0.wnmnk0w.mongodb.net/?retryWrites=true&w=majority";

  $mongoose = new MongoDBConnectExt();

  $connectMongoDB = $mongoose->connectMongoDB($uri);

  session_start();

  function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[random_int(0, $charactersLength - 1)];
    }
    return $randomString;
  }

  if(!isset($_SESSION['email'])){
    echo '<script>alert("Vui lòng đăng nhập!!!!")</script>';
    echo "<script>window.location = 'sign_in.php';</script>";
  }
  else{
    $uid = preg_match('/(.*?)@/', $_SESSION['email'], $matches);
    echo '<h3>Nihao, ' .$_SESSION['email']. '</h3>';   
  }
  
  if(isset($_POST['btnLogout'])){
    unset($_SESSION['email']);
    header("Location: sign_in.php");
  }


  if(isset($_POST['btnScan'])){
    $strHash = $matches[1].generateRandomString(10);
    $antiXss->xss_clean($_POST['txtUrlInput']);
    if($antiXss->isXssFound()){
      echo '<script>alert("URL không hợp lệ!!!!")</script>';
      
    }else{
      if (filter_var($_POST['txtUrlInput'], FILTER_VALIDATE_URL) === FALSE) {
        echo '<script>alert("URL không hợp lệ!!!!")</script>';
        
      }else{
        $data = array(
          'url' => $_POST['txtUrlInput'], 
          'hash' => $strHash
        );

        $data_string = json_encode($data);


        $curl = curl_init();

        curl_setopt($curl, CURLOPT_URL, 'http://127.0.0.1:6886/api/');
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($curl, CURLOPT_POSTFIELDS, $data_string);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',       
        ));

        curl_exec($curl);

        if(curl_errno($curl)){
          echo '<script>alert("Server API không hoạt động")</script>';
          echo "<script>window.location = 'main.php';</script>";
          curl_close($curl);
        }
        else{
          curl_close($curl);

          $mongoose->updateManyData($connectMongoDB, "WAPTT", "DataScan",['hash' => 'hash_key'],['hash' => $strHash]);

          
          $strData = [
            "hash"=>$strHash,
            "uid"=>$matches[1],
            "url"=>$_POST['txtUrlInput'],
            "date"=>date("d/m/Y H:i:s A")
          ];

          $mongoose->insertData($connectMongoDB, "WAPTT", "HistoryScan", $strData);
            
          echo '<script>alert("Quét thành công")</script>';
          echo "<script>window.location = 'main.php';</script>";
        }

        
      }
    }
    
  }

  $dataRender = $mongoose->findDataInDB($connectMongoDB, "WAPTT", "HistoryScan", ["uid" => $matches[1]]);
  $sttData = 1;
  
  
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="style.css">

    <title>WAPTT</title>
</head>
<body>
    <main>
        <section>
            <form action="main.php" method="POST">
              <button type="submit" name="btnLogout" >Log out</button>           
            </form>
            <h2>Capstone Project 2 - C2NE.04</h2>
            <div class="wrapper">
                <div class="main-title">
                    <div class="scanner" id="scanner">Online Scanning</div>
                    <span class="line"></span>
                    <div class="history" id="scan-history">History Scanning</div>
                </div>            
                <div class="scan-slider">
                    <div class="scanning" id="form-scanner">
                      <form action="main.php" method="POST">
                          <input type="search" id="scanning-input" placeholder="Enter URL..." name="txtUrlInput">
                          <button id="scan" type="submit" name="btnScan">SCAN</button>
                      </form>
                    </div>
                    <div class="scan-history" id="form-history" hidden>
                      <table>
                        <thead>
                          <tr>
                            <th>Index</th>
                            <th>URL Scanner</th>
                            <th>Time Scan</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                        <?php
                            foreach ($dataRender as $eachData){
                              echo '<tr>
                                        <td>'.$sttData.'</td>
                                        <td>'.$eachData['url'].'</td>
                                        <td>'.$eachData['date'].'</td>
                                        <td><a href="form-reports.php?url='.$eachData['url'].'&hash='.$eachData['hash'].'">View</a></td>
                                    </tr>';
                              $sttData++;
                            }
                        ?>
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
            </div>
        </section>
    </main>
    <script src="./main.js"></script>
</body>
</html>