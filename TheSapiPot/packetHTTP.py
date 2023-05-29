import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import numpy as np
import pickle
from urllib.parse import urlparse, parse_qs,unquote_plus
import re



class modelHTTP:
    def __init__(self,request):
        self.max_length = 100
        self.trunc_type='post'
        self.padding_type='post'
        self.request = request
        #load model
        self.model = tf.keras.models.load_model("TheSapiPot/model/SentAn")
        #load data
        with open('TheSapiPot/model/tokenizer_sentAn.pickle', 'rb') as handle:
            self.tokenizer,self.labels_len = pickle.load(handle)
    
    def unquote_link(self,url_link):
        try:
            link = unquote_plus(unquote_plus(url_link))
            return link
        except TypeError:
            return link
        
        
    def make_url(self, request):
        headers,payload = request.split('\r\n\r\n')
        if payload:
            referer = None
            for header in headers.split('\r\n'):
                if header.startswith('Referer:'):
                    referer = header.split('Referer: ')[1]
            return(referer + '?' + payload)
        else:
            header = headers.split('\r\n')
            head = header[0].split(" ")
            return(head[1])
                    

    def extract_variables_from_requests(self,request):
        url = self.make_url(request)
        url = self.unquote_link(url)
        parsed_url = urlparse(url)
        query_string = parsed_url.query
        query_vars = parse_qs(query_string)  
        return query_vars
        # variables = []
        # for var in query_vars:
        #     if var == 'user_token':
        #         continue
        #     variables.append(query_vars[var][0])  
        
        # return ' '.join(variables)

    def spaced_variables(self,var_list):
        escaped_string = re.sub(r'([:()])', r'\\\1', var_list)
        spaced_string = ' '.join(escaped_string)
        return spaced_string

    # copy from here

    def predicts(self):
        # print(self.request)
        query_vars = self.extract_variables_from_requests(self.request)
        # print("var", query_vars)
        if query_vars:
            sentence = []
            sentence.append(self.spaced_variables(query_vars))
            sequences = self.tokenizer.texts_to_sequences(sentence)
            padded = pad_sequences(sequences, maxlen=self.max_length, padding=self.padding_type, truncating=self.trunc_type)
            results = self.model.predict(padded,verbose=0)[0]
            if np.sum(results) > .4:
                data_percentages = results * 100
                output = ''
                for i in range(len(self.labels_len)):
                    output += f'{self.labels_len[i]}: {data_percentages[i]:.2f}% '
                output = output.strip()
                return(output)
            else:
                pass
            # for i,x in enumerate(results):
            #     print(x,i)
            #     percent = np.round(x*100, 2) 
            #     predict += f"[{i+1}] "+self.labels_len[i]+" "+str(int(percent[i]))+"% \n"
            # return(predict)
        else:
            pass

# data ="""GET /dvwa/js/add_event_listeners.js HTTP/1.1
# Host: 192.168.8.189
# Connection: keep-alive
# User-Agent: Mozilla/5.0 (Linux; Android 6.0.1; CPH1701) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Mobile Safari/537.36
# Accept: */*
# Referer: http://192.168.8.189/dvwa/index.php
# Accept-Encoding: gzip, deflate
# Accept-Language: en-US,en;q=0.9
# Cookie: PHPSESSID=52e4g6dn48372ep0atfkljcihu; security=impossible"""
# data1 = """POST /dvwa/login.php HTTP/1.1?name=<!--\x3E<img src=xxx:x onerror=javascript:alert(1)> -->
# Host: 192.168.8.189
# Connection: keep-alive
# Content-Length: 91
# Cache-Control: max-age=0
# Upgrade-Insecure-Requests: 1
# Origin: http://192.168.8.189
# Content-Type: application/x-www-form-urlencoded
# User-Agent: Mozilla/5.0 (Linux; Android 10; M2010J19CG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
# Referer: http://192.168.8.189/dvwa/login.php
# Accept-Encoding: gzip, deflate
# Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
# Cookie: PHPSESSID=7a8r074s4po0nddnk0b8ig6eah; security=impossible

# username=kali&password=password1" OR 1 = 1 -- -&Login=Login&user_token=50dd079bc51fe9993a425ede60e529a5"""
# data2 = """POST /dvwa/vulnerabilities/brute/ HTTP/1.1
# Host: 192.168.8.189
# Connection: keep-alive
# Content-Length: 85
# Cache-Control: max-age=0
# Upgrade-Insecure-Requests: 1
# Origin: http://192.168.8.189
# Content-Type: application/x-www-form-urlencoded
# User-Agent: Mozilla/5.0 (Linux; Android 6.0.1; CPH1701) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Mobile Safari/537.36
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
# Referer: http://192.168.8.189/dvwa/vulnerabilities/brute/
# Accept-Encoding: gzip, deflate
# Accept-Language: en-US,en;q=0.9
# Cookie: PHPSESSID=7mn6o62ofateb14j3fhru2fujp; security=impossible

# username=Hsahs&password=shdhd&Login=Login&user_token=1ec147b994724a35bc45bd7b5beb91a8"""
# prd = modelHTTP(request=data2)
# print(prd.predicts())