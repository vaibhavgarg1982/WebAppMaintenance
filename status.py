import time
import winsound
import requests
import argparse

parser = argparse.ArgumentParser(description="Check the status of the server")
parser.add_argument(
    "--url", type=str, default="http://1000rnd2000459:5000/", help="The url to check"
)
parser.add_argument(
    "--interval", type=int, default=300, help="The interval in seconds to check the url"
)
args = parser.parse_args()

print(f"{args}")

duration = 2000  # milliseconds
freq = 2500  # Hz
while True:

    try:
        r = requests.get(args.url)
    except requests.exceptions.RequestException as e:
        winsound.Beep(freq, duration)
        print(f"{e}")
        exit()
    # r = requests.get('http://1000rnd2000459:5000/')
    # print (r.status_code, time.ctime())
    print(f"{r.status_code = } at {time.ctime()}")

    if r.status_code != 200:
        print("status code is not 200")
        winsound.Beep(freq, duration)

    time.sleep(args.interval)
