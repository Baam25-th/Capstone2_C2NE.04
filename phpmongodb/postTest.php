<?php


    $data = array(
        'url' => 'https://testvulncaps2.000webhostapp.com/', 
        'hash' => 'Test'
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

    $result = curl_exec($curl);

    print_r($result);

    curl_close($curl);


    

?>