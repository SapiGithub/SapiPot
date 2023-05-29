import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import numpy as np
import pickle
from urllib.parse import urlparse, parse_qs,unquote_plus
import re

class modelHTTP:
    def __init__(self,request):
        self.max_length = 300
        self.trunc_type='post'
        self.padding_type='post'
        self.request = request
        self.model = tf.keras.models.load_model("TheSapiPot/model/SentAn")
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

    def spaced_variables(self,var_list):
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
            if np.sum(results) > .4:
                data_percentages = results * 100
                output = ''
                for i in range(len(self.labels_len)):
                    output += f'{self.labels_len[i]}: {data_percentages[i]:.2f}% '
                output = output.strip()
                return(output)
            else:
                pass
        else:
            pass