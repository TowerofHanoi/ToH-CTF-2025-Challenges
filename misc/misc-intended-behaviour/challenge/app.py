import os
import base64
from tensorflow import keras

UPLOAD_FOLDER = "/tmp"

def upload_model():
    model_name = input("Enter the name of the model file: ")
    model_path = os.path.join(UPLOAD_FOLDER, os.path.basename(model_name))
    
    model_base_64 = input("Enter base64 encoded model file: ")
    model_content = base64.b64decode(model_base_64)
    
    with open(model_path, "wb") as model_file:
        model_file.write(model_content)
    
    keras.models.load_model(model_path, safe_mode=True)

if __name__ == "__main__":
    upload_model()