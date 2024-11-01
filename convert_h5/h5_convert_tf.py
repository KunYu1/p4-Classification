import tensorflow as tf
import sys
import os
from pathlib import Path

# usage: python convert.py <h5 model file path>

def convert():
    if (len(sys.argv) != 2):
        print("argument error!\nusage: python convert.py <h5 model file path>")            
    model = tf.keras.models.load_model(sys.argv[1])
    model.save("./{}".format(Path(sys.argv[1]).stem), save_format='tf')


if __name__ == "__main__":
    convert()