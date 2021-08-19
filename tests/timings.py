from TimingAttacks import TimingAttacks
import json


def main():
    while True:
        with open("httpinfo.json", "r") as f:
            data = f.read()
        authenticate = TimingAttacks.Authenticate("test username")
        authenticate.validate(data)


if __name__ == '__main__':
    main()
