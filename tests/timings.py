from TimingAttacks import TimingAttacks


def main():
    while True:
        length = TimingAttacks.crack_length("test.txt", "test username")

        password = TimingAttacks.crack_password("test.txt", "test username", length)


if __name__ == '__main__':
    main()
