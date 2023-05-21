import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import os

uri = "mongodb+srv://crackervn029:lethithuy1011@cluster0.wnmnk0w.mongodb.net/WAPTT?retryWrites=true&w=majority"

# Create a new client and connect to the server
client = MongoClient(uri)

# initialize an HTTP session & set the browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        "fatal error",
        "msqlclien",
        # SQL Server
        "unclosed quotation mark after the character string",
        "warning:",
        # Oracle
        "quoted string not properly terminated",
        "oracle error",
        "warning: oracle",

    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False

def scan_sql_injection(url, hash_key):
    
    data_results = {
        "type" : "XSS",
    }
    my_payloads =[]
    with open("payloads_sqli.txt", "r") as f:
        list_payloads = f.readlines()
    for line in list_payloads:
        my_payloads.append(line.strip("\n"))

    #test url sqli

    for c in my_payloads:
        # add quote/double quote character to the URL
        new_url = f"{url}{c}"
        # make the HTTP request
        res = s.get(new_url)
        # print(res.content.decode().lower())
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself, 
            # no need to preceed for extracting forms and submitting them
            collection = client["WAPTT"]["DataScan"]
            data_collection = {
                "hash": hash_key,
                "type":"SQLi",
                "url":url,
                "method": form_details["method"].upper(),
                "payload": payload
            }
            collection.insert_one(data_collection)
            return

    #Test HTML Form
    forms = get_all_forms(url)

    for form in forms:
        form_details = get_form_details(form)
        # print(form_details["inputs"])
        
        for payload in my_payloads:
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + payload
                    except:
                        pass

                elif input_tag["type"] != "submit":

                    data[input_tag["name"]] = f"admin{payload}"

            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            
            # print(res.content.decode().lower())
            
            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                    collection = client["WAPTT"]["DataScan"]
                    data_collection = {
                        "hash": hash_key,
                        "type":"SQLi",
                        "url":url,
                        "method": form_details["method"].upper(),
                        "payload": payload
                    }
                    collection.insert_one(data_collection)
                    # print("Success!!")
                    # print("[+] SQL Injection vulnerability detected, link:", url)
                    # print("[+] Method:", form_details["method"])
                    # print("[+] Payload:", payload)
                    # print(data_collection)
                    return
            
    
def start(hash_key):
    listUrls = []
    with open(hash_key+'_urls.txt','r') as f:
        storageUrl = f.readlines()
    for line in storageUrl:
        listUrls.append(line.strip("\n"))
    for url in listUrls:
        scan_sql_injection(url,hash_key)
    if os.path.exists(hash_key+'_urls.txt'):
        os.remove(hash_key+'_urls.txt')
    


