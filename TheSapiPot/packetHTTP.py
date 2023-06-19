import tensorflow as tf
from scapy.all import *
from scapy.layers.http import HTTPRequest
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import numpy as np
import pickle
from urllib.parse import unquote_plus,urlparse, parse_qs, urlencode, urlunparse
import re

class modelHTTP:
    def __init__(self,request: Packet):
        self.max_length = 300
        self.trunc_type='post'
        self.padding_type='post'
        self.request = request
        self.model = tf.keras.models.load_model("TheSapiPot/model/SentAn")
        with open('TheSapiPot/model/tokenizer_sentAn.pickle', 'rb') as handle:
            self.tokenizer,self.labels_len = pickle.load(handle)
    
    def unquote_link(self,url_link:str):
        try:
            link = unquote_plus(unquote_plus(url_link))
            return link
        except TypeError:
            return link
        
        
    def make_url(self, request: Packet):
        httpRequest = request[HTTPRequest]
        if request.haslayer(Raw):
            return httpRequest.Path.decode()+"?"+request[Raw].load.decode()
        else:
            return httpRequest.Path.decode()
                    
    def extract_variables_from_requests(self,request: Packet):
        url = self.make_url(request)
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            if 'user_token' in query_params:
                del query_params['user_token']

            query_values = [value for values in query_params.values() for value in values]
            query_string = ' '.join(query_values)

            return query_string
        except ValueError:
            return None

    def spaced_variables(self,var_list:str):
        escaped_string = re.sub(r'([:()])', r'\\\1', var_list)
        spaced_string = ' '.join(escaped_string)
        return spaced_string

    def predicts(self):
        query_vars = self.extract_variables_from_requests(self.request)
        if query_vars:
            sentence = []
            sentence.append(self.spaced_variables(query_vars))
            sequences = self.tokenizer.texts_to_sequences(sentence)
            padded = pad_sequences(sequences, maxlen=self.max_length, padding=self.padding_type, truncating=self.trunc_type)
            results = self.model.predict(padded,verbose=0)[0]
            if np.sum(results) > .5:
                data_percentages = results * 100
                output = ''
                for i in range(len(self.labels_len)):
                    output += f'\n{self.labels_len[i]}: {data_percentages[i]:.2f}% '
                output = output.strip()
                return(output)
            else:
                return None
        else:
            return None
