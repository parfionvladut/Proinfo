#!/usr/bin/python
import os
import sys
import pickle
import argparse
import re
import numpy

from sklearn import tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import FeatureHasher

def get_string_features(path,hasher):
    chars = r" -~"
    min_length = 5
    string_regexp = '[%s]{%d,}' % (chars, min_length)
    file_object = open(path)
    data = file_object.read()
    pattern = re.compile(string_regexp)
    strings = pattern.findall(data)

    string_features = {}
    for string in strings:
        string_features[string] = 1

    hashed_features = hasher.transform([string_features])
    hashed_features = hashed_features.todense()
    hashed_features = numpy.asarray(hashed_features)
    hashed_features = hashed_features[0]

    print ("Extracted {0} strings from {1}".format(len(string_features),path))

    return hashed_features

def scan_file(path):
    if not os.path.exists("saved_detector.pkl"):
       print ("Train a detector before scanning files.\n")
       sys.exit(1)

    with open("saved_detector.pkl") as saved_detector:
       classifier, hasher = pickle.load(saved_detector)

    features = get_string_features(path,hasher)
    result_proba = classifier.predict_proba([features])[:,1]

    if result_proba > 0.5:
       print ("It appears this file is malicious! %d " % result_proba)
    else:
       print ("It appears this file is benign. %d " % result_proba)

def train_detector(benign_path,malicious_path,hasher):
    def get_training_paths(directory):
        targets = []
    
        for path in os.listdir(directory):
            targets.append(os.path.join(directory,path))
    
        return targets

    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)

    X = [get_string_features(path,hasher) for path in malicious_paths + benign_paths]
    y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]

    classifier = tree.RandomForestClassifier(64)
    classifier.fit(X,y)

    pickle.dump((classifier,hasher),open("saved_detector.pkl","w+"))

def get_training_data(benign_path,malicious_path,hasher):
    def get_training_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory,path))
        return targets

    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)

    X = [get_string_features(path,hasher) for path in malicious_paths + benign_paths]
    y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]

    return X, y	

parser = argparse.ArgumentParser("get windows object vectors for files")
parser.add_argument("—cale_malware",default=None,help="Calea catre fisierele de training malware")
parser.add_argument("—cale_benigne",default=None,help="Calea catre fisierele de training benigne ")
parser.add_argument("—cale_fisier",default=None,help="Fisier de scanat")

args = parser.parse_args()
hasher = FeatureHasher(20000)

if args.malware_paths and args.benignware_paths:
   train_detector(args.benignware_paths,args.malware_paths,hasher)
elif args.scan_file_path:
   scan_file(args.scan_file_path)
else:
   print ("[*] Nu a fost specificata calea de scanare " \
          " si nici caile catre fisierele de training malware si benigne \n")
parser.print_help()