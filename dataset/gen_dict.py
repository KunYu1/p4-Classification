import json
from os import listdir
from os.path import isfile, isdir, join

dataset_path = "./archive/Network-Traffic-Dataset/"
onlydirs = [f for f in listdir(dataset_path) if isdir(join(dataset_path, f))]

dir_dict = {i: folder_name for i, folder_name in enumerate(onlydirs)}

with open('dict.json', 'w', encoding='utf-8') as json_file:
    json.dump(dir_dict, json_file, ensure_ascii=False, indent=4)

dir_dict_rev = {folder_name: i for i, folder_name in enumerate(onlydirs)}

with open('classes.json', 'w', encoding='utf-8') as json_file:
    json.dump(dir_dict_rev, json_file, ensure_ascii=False, indent=4)