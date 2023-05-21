<?php
    require_once __DIR__ . '/vendor/autoload.php';

    class MongoDBConnectExt{

        public function __construct(){
            
        }
        
        public function connectMongoDB($uri){
            $client = new MongoDB\Client($uri);

            return $client;
        }

        public function insertUsers($client, $dbName, $collectionName, $email, $password){
            $dbWaptt = $client->$dbName;
            $usercollection = $dbWaptt->$collectionName;
            preg_match('/(.*?)@/', $email, $matches);

            $usercollection->insertOne([
                "email"=>$email,
                "password"=>$password,
                "uid"=>$matches[1]
            ]);
        }

        public function insertData($client, $dbName, $collectionName, $strData){
            $dbWaptt = $client->$dbName;
            $usercollection = $dbWaptt->$collectionName;

            $usercollection->insertOne($strData);
        }

        public function findDataInDB($client, $dbName, $collectionName, $data){

            $dbWaptt = $client->$dbName;
            $usercollection = $dbWaptt->$collectionName;

            $document = $usercollection->find($data)->toArray();

            return $document;
        }

        public function findUserInDB($client, $dbName, $collectionName, $email){

            $dbWaptt = $client->$dbName;
            $usercollection = $dbWaptt->$collectionName;

            $document = $usercollection->find(['email' => $email])->toArray();

            return $document;
        }

        public function checkUserInDB($client, $dbName, $collectionName, $email){

            $dbWaptt = $client->$dbName;
            $usercollection = $dbWaptt->$collectionName;

            $document = $usercollection->find(['email' => $email])->toArray();

            if(count($document) == 0)
                return true;
            else
                return false;
        }

        public function updateManyData($client, $dbName, $collectionName, $query, $collectUpdate){
            $dbWaptt =  $client->$dbName;

            $usercollection = $dbWaptt->$collectionName;

            $usercollection->updateMany(
                $query,
                ['$set' => $collectUpdate]
            );
        }

        function IsNullOrEmptyString($str){
            if($str === null || trim($str) === '')
                return true;
            else 
                return false;
        }
    }

?>