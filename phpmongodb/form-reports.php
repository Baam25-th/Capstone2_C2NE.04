<?php
    
    include "mongoExt.php";

    
    $uri = "mongodb+srv://crackervn029:lethithuy1011@cluster0.wnmnk0w.mongodb.net/?retryWrites=true&w=majority";
    
    $mongoose = new MongoDBConnectExt();

    if($_GET['url'] == "" && $_GET['hash'] == ""){
        header("Location: main.php");
    }
    else{
          
        $connectMongoDB = $mongoose->connectMongoDB($uri);
        
        $_url = $_GET['url'];
        $_hash = $_GET['hash'];

        $indexSQLi = 1;
        $dataSQLi = $mongoose->findDataInDB($connectMongoDB, "WAPTT", "DataScan", ["hash" => $_hash, "type" => "SQLi"]);
        $indexXSS = 1;
        $dataXSS = $mongoose->findDataInDB($connectMongoDB, "WAPTT", "DataScan", ["hash" => $_hash, "type" => "XSS"]);
        
        
        
    }
        
    

?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAPTT Form Reports</title>
    <link rel="stylesheet" href="style-reports.css">
</head>
<body>
    <main>
        <div class="title">
            <h1>Website Vulnerability Scanner Report</h1>
            <div class="target-name">
                <h3>TARGET</h3>
                <?php
                    echo '<span>'.$_url.'</span>';
                ?>
            </div>
        </div>
        <h2>Findings</h2>
        <section class="vuln-reports">
            <div class="vuln-reports__sqli">
                <h3 id="sqli_show">SQL Injection</h3>
                <div class="reports__sqli--content" id="description-sql" hidden>
                    <h4>Risk description:</h4>
                        <p>We found that the web application is vulnerable to SQL Injection attacks. SQL Injection is a vulnerability caused by improper input sanitization and allows an attacker to inject arbitrary SQL commands and execute them directly on the database</p>
                        
                        <p>The risk exists that an attacker gains unauthorized access to the information from the database of the application. They could extract information such as: application usernames, passwords, client information and other application specific data</p>

                    <h4>Recommendation:</h4>
                        <p>We recommend implementing a validation mechaism for all the data received from the users. The best way to protect against SQL Injection is to use prepared statements for every SQL query performed on the database. Otherwise, the user input can also be sanitized using dedicated methods such as: mysqli_real_escape_string.</p>
                    <h4>References:</h4>
                        <p><a href="https://www.owasp.org/index.php/SQL_Injection">https://www.owasp.org/index.php/SQL_Injection</a></p>
                        <p><a href="https://www.owasp.org/index.php/SQL_Injection">https://www.owasp.org/index.php/SQL_Injection</a></p>
                        <p><a href="https://www.owasp.org/index.php/SQL_Injection">https://www.owasp.org/index.php/SQL_Injection</a></p>
                    
                    <div class="vuln-description">
                        <table>
                            <thead>
                                <tr>
                                    <th>Index</th>
                                    <th>URL</th>
                                    <th>Method</th>
                                    <th>Payload</th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php
                                foreach ($dataSQLi as $eachData){
                                echo '<tr>
                                        <td>'.$indexSQLi.'</td>
                                        <td>'.$eachData['url'].'</td>
                                        <td>'.$eachData['method'].'</td>
                                        <td>'.$eachData['payload'].'</td>
                                      </tr>';
                                $indexSQLi++;                       
                                }
                            ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- REport XSS -->

            <div class="vuln-reports__xss">
                <h3 id="xss_show">Cross-Site-Scripting</h3>
                <div class="reports__xss--content" id="description-xss" hidden>
                    <h4>Risk description:</h4>
                        <p>The web applications is vulnerable to reflected Cross-Site-Scripting attacks. The risk exists that a malicious actor inject JavaScript code and runs its in the context of a user session in the application. This could potentially lead to various effects such as stealing session cookies, calling application, features on behalf of another user, exploiting browser vulnerabilities</p>
                        
                        <p>Successfull explitation of Cross-Site-Scripting attacks requires human interaction (ex. determine the user to access a special link by social engineering)</p>

                    <h4>Recommendation:</h4>
                        <p>There are serveral ways to mitigate XSS attacks. We recommend to:</p>
                        <p>- Never trust user input</p>
                        <p>- Always encode and escape user input (using a Security Encoding Library)</p>
                        <p>- Use the HTTPOnly cookie flag to protect from cookie theft</p>
                        <p>- Implement Content Security Policy</p>
                        <p>- Use the X-XSS-Protection Response Header</p>
                    <h4>References:</h4>
                        <p><a href="https://www.owasp.org/index.php/SQL_Injection">https://www.owasp.org/index.php/SQL_Injection</a></p>
                        <p><a href="https://www.owasp.org/index.php/SQL_Injection">https://www.owasp.org/index.php/SQL_Injection</a></p>
                        <p><a href="https://www.owasp.org/index.php/SQL_Injection">https://www.owasp.org/index.php/SQL_Injection</a></p>
                    
                    <div class="vuln-description">
                        <table>
                            <thead>
                                <tr>
                                    <th>Index</th>
                                    <th>URL</th>
                                    <th>Method</th>
                                    <th>Payload</th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php
                                foreach ($dataXSS as $eachData){
                                echo '<tr>
                                        <td>'.$indexXSS.'</td>
                                        <td>'.$eachData['url'].'</td>
                                        <td>'.$eachData['method'].'</td>
                                        <td>'.htmlspecialchars($eachData['payload']).'</td>
                                      </tr>';
                                $indexXSS++;                       
                                }
                            ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>
    </main>
    <script src="./report-form.js"></script>
</body>
</html>