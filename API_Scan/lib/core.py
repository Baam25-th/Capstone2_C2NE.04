from lib.helper.helper import *
from random import randint
from bs4 import BeautifulSoup
from urllib.parse import urljoin,urlparse,parse_qs,urlencode
from lib.helper.Log import *
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

uri = "mongodb+srv://crackervn029:lethithuy1011@cluster0.wnmnk0w.mongodb.net/WAPTT?retryWrites=true&w=majority"

# Create a new client and connect to the server
client = MongoClient(uri)

class core:
	
	@classmethod
	def generate(self):		
		FUNCTION=[
			"<script>prompt(5000/200)</script>",
			"<script>alert(6000/3000)</script>",
		]
		for payload in FUNCTION:
			yield payload
			
	@classmethod
	def post_method(self):
		bsObj=BeautifulSoup(self.body,"html.parser")
		forms=bsObj.find_all("form",method=True)
		
		for form in forms:
			try:
				action=form["action"]
			except KeyError:
				action=self.url
				
			if form["method"].lower().strip() == "post":
				for i in range(len(self.payload)):
					Log.warning("Target have form with POST method: "+C+urljoin(self.url,action))
					Log.info("Collecting form input key.....")
					
					keys={}
					for key in form.find_all(["input","textarea"]):
						try:
							if key["type"] == "submit":
								Log.info("Form key name: "+G+key["name"]+N+" value: "+G+"<Submit Confirm>")
								keys.update({key["name"]:key["name"]})
					
							else:
								Log.info("Form key name: "+G+key["name"]+N+" value: "+G+self.payload[i])
								keys.update({key["name"]:self.payload[i]})
								
						except Exception as e:
							Log.info("Internal error: "+str(e))
					
					Log.info("Sending payload (POST) method...")
					req=self.session.post(urljoin(self.url,action),data=keys)
					if self.payload[i] in req.text:
						Log.high("Detected XSS (POST) at "+urljoin(self.url,req.url))
						Log.high("Post data: "+str(keys))
					else:
						Log.info("This page is safe from XSS (POST) attack but not 100% yet...")
	
	@classmethod
	def get_method_form(self):
		bsObj=BeautifulSoup(self.body,"html.parser")
		forms=bsObj.find_all("form",method=True)
		data_resurlts = {}
		for form in forms:
			try:
				action=form["action"]
			except KeyError:
				action=self.url
				
			if form["method"].lower().strip() == "get":
				Log.warning("Target have form with GET method: "+C+urljoin(self.url,action))
				Log.info("Collecting form input key.....")
				
				keys={}
				for i in range(len(self.payload)):
					for key in form.find_all(["input","textarea"]):
						try:
							if key["type"] == "submit":
								Log.info("Form key name: "+G+key["name"]+N+" value: "+G+"<Submit Confirm>")
								keys.update({key["name"]:key["name"]})
					
							else:
								Log.info("Form key name: "+G+key["name"]+N+" value: "+G+self.payload[i])
								keys.update({key["name"]:self.payload[i]})
								
						except Exception as e:
							Log.info("Internal error: "+str(e))
							try:
								Log.info("Form key name: "+G+key["name"]+N+" value: "+G+self.payload[i])
								keys.update({key["name"]:self.payload[i]})
							except KeyError as e:
								Log.info("Internal error: "+str(e))
							
					Log.info("Sending payload (GET) method...")
					req=self.session.get(urljoin(self.url,action),params=keys)
					if self.payload[i] in req.text:
						Log.high("Detected XSS (GET) at "+urljoin(self.url,req.url))
						Log.high("GET data: "+str(keys))
						collection = client["WAPTT"]["DataScan"]
						data_collection = {
							"hash": "hash_key",
							"type":"XSS",
							"url":self.url,
							"method": form["method"].upper().strip(),
							"payload": self.payload[i]
						}
						
						collection.insert_one(data_collection)
						return
					else:
						Log.info("This page is safe from XSS (GET) attack but not 100% yet...")
		
	@classmethod
	def get_method(self):
		bsObj=BeautifulSoup(self.body,"html.parser")
		links=bsObj.find_all("a",href=True)
		for a in links:
			url=a["href"]
			if url.startswith("http://") is False or url.startswith("https://") is False or url.startswith("mailto:") is False:
				base=urljoin(self.url,a["href"])
				query=urlparse(base).query
				for i in range(len(self.payload)):
					if query != "":
						Log.warning("Found link with query: "+G+query+N+" Maybe a vuln XSS point")
						
						query_payload=query.replace(query[query.find("=")+1:len(query)],self.payload[i],1)
						test=base.replace(query,query_payload,1)
						
						query_all=base.replace(query,urlencode({x: self.payload[i] for x in parse_qs(query)}))
						
						Log.info("Query (GET) : "+test)
						Log.info("Query (GET) : "+query_all)
						
						_respon=self.session.get(test)
						if self.payload[i] in _respon.text or self.payload[i] in self.session.get(query_all).text:
							Log.high("Detected XSS (GET) at "+_respon.url)
							with open('xsscon_results.txt','a') as f:
								output = f"[XSS Found] {self.url} - Payload: {self.payload[i]}"
								f.write(output + "\n")
						else:
							Log.info("This page is safe from XSS (GET) attack but not 100% yet...")
		
	@classmethod
	def main(self,url,proxy,headers,payload,cookie,method=2):
	
		
		print(W+"*"*15)
		self.payload=payload
		self.url=url

		self.session=session(proxy,headers,cookie)
		Log.info("Checking connection to: "+Y+url)	
		try:
			ctr=self.session.get(url)
			self.body=ctr.text
		except Exception as e:
			Log.high("Internal error: "+str(e))
			return
		
		if ctr.status_code > 400:
			Log.info("Connection failed "+G+str(ctr.status_code))
			return 
		else:
			Log.info("Connection estabilished "+G+str(ctr.status_code))
		
		if method >= 2:
			self.post_method()
			self.get_method()
			self.get_method_form()
			
		elif method == 1:
			self.post_method()
			
		elif method == 0:
			self.get_method()
			self.get_method_form()
		# with open("xsscon_results.txt", "r") as f:
		# 	lines = f.readlines()
		
		# lines = list(set(lines))
		# with open("xsscon_results.txt", "w") as f:
		# 	f.writelines(lines)
		
