from TimingAttacks import TimingAttacks


def main():
    while True:
        authenticate = TimingAttacks.Authenticate("test username")
        authenticate.validate()


if __name__ == '__main__':
    main()
