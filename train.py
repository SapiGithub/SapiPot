# import nltk
# from nltk.stem.lancaster import LancasterStemmer
# stemmer = LancasterStemmer()

# import numpy
# import tensorflow
# from tensorflow import keras
# import random
# import json
# import pickle

# with open("data.json") as file:
#     data = json.load(file)

# try:
#     with open("data.pickle", "rb") as f:
#         payloads, labels, training, output = pickle.load(f)
# except:
#     payloads = []
#     labels = []
#     docs_x = []
#     docs_y = []

#     for intent in data["intents"]:
#         for pattern in intent["patterns"]:
#             wrds = nltk.word_tokenize(pattern)
#             payloads.extend(wrds)
#             docs_x.append(wrds)
#             docs_y.append(intent["tag"])

#         if intent["tag"] not in labels:
#             labels.append(intent["tag"])

#     # payloads = [stemmer.stem(w.lower()) for w in payloads if w != "?"]
#     payloads = sorted(list(set(payloads)))

#     labels = sorted(labels)

#     training = []
#     output = []

#     out_empty = [0 for _ in range(len(labels))]

#     for x, doc in enumerate(docs_x):
#         bag = []

#         # wrds = [stemmer.stem(w.lower()) for w in doc]

#         for w in payloads:
#             if w in doc:
#                 bag.append(1)
#             else:
#                 bag.append(0)

#         output_row = out_empty[:]
#         output_row[labels.index(docs_y[x])] = 1

#         training.append(bag)
#         output.append(output_row)
        
#     training = numpy.array(training)
#     output = numpy.array(output)
#     with open("data.pickle", "wb") as f:
#         pickle.dump((payloads, labels, training, output), f)

# model = keras.Sequential([
#     keras.layers.Input(shape=[len(training[0])]),
#     keras.layers.Dense(8, activation='relu'),
#     keras.layers.Dense(8, activation='relu'),
#     keras.layers.Dense(len(output[0]), activation='softmax')
# ])

# model.compile(optimizer='adam',
#               loss='categorical_crossentropy',
#               metrics=['accuracy'])
# try:
#     model.load("model/my_model")
# except:
#     model.fit(training, output, epochs=1000, batch_size=8, verbose=1)
#     model.save("model/my_model")

# def bag_of_payloads(s, payloads):
#     bag = []
#     for i in s.splitlines():
#         if i != "":
#             pack = [0 for _ in range(len(payloads))]

#             s_payloads = nltk.word_tokenize(i)
#             # s_payloads = [stemmer.stem(word.lower()) for word in s_payloads]

#             for se in s_payloads:
#                 for i, w in enumerate(payloads):
#                     if w in se:
#                         pack[i] = 1
#             bag.append(pack)
#     return bag


# payload_inp = """
# POST /dvwa/login.php HTTP/1.1
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

# username=admin&password=password&Login=Login&user_token=50dd079bc51fe9993a425ede60e529a5
# """

# var = bag_of_payloads(payload_inp, payloads)
# print(var)
# results = model.predict(var)
# print(results)
# results_index = numpy.argmax(results)
# # print(results_index)
# tag = labels[results_index]

# for tg in data["intents"]:
#     if tg['tag'] == tag:
#         responses = tg['responses']
# print(responses)
# # def chat():
# #     print("Start talking with the bot (type quit to stop)!")
# #     while True:
# #         inp = input("You: ")
# #         if inp.lower() == "quit":
# #             break

# #         results = model.predict([bag_of_payloads(inp, payloads)])
# #         # print(results)
# #         results_index = numpy.argmax(results)
# #         # print(results_index)
# #         tag = labels[results_index]

# #         for tg in data["intents"]:
# #             if tg['tag'] == tag:
# #                 responses = tg['responses']

# #         print(random.choice(responses))

# # chat()
from scapy.all import *
import scapy.all as scapy
sniff(prn=lambda p: p.summary(), iface="wlan0", store=False, filter=f'arp')