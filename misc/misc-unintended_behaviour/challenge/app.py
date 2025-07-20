from tensorflow import keras
import os
import zipfile
import base64

UPLOAD_FOLDER = "/tmp"
KERAS_FILE = "model.keras"

def check_config_file():
    config_path = os.path.join(UPLOAD_FOLDER, "config.json")
    if not os.path.exists(config_path):
        return False
    
    try:
        with open(config_path, "r") as f:
            config = f.read()
        config = config.lower()
        if "lambda" in config:
            return False
    except Exception:
        return False
    return True


def upload_model():
    config_base_64 = input("Enter base64 encoded config file: ")
    metadata_base_64 = input("Enter base64 encoded metadata file: ")
    weights_base_64 = input("Enter base64 encoded weights file: ")
    
    files = {
        "config.json": base64.b64decode(config_base_64),
        "metadata.json": base64.b64decode(metadata_base_64),
        "model.weights.h5": base64.b64decode(weights_base_64)
    }

    for filename, filecontent in files.items():
        with open(os.path.join(UPLOAD_FOLDER, filename), "wb") as file:
            file.write(filecontent)
        
    if not check_config_file():
        exit(1)

    keras_path = os.path.join(UPLOAD_FOLDER, KERAS_FILE)
    with zipfile.ZipFile(keras_path, "w") as zf:
        for filename in files.keys():
            zf.write(os.path.join(UPLOAD_FOLDER, filename), arcname=filename)

    keras.models.load_model(keras_path, safe_mode=True)

if __name__ == "__main__":
    upload_model()