import random
import string


def build_block(size=10):
    return ''.join(random.choice(string.ascii_letters) for _ in range(size))


def build_email():
    random_string = build_block()
    return random_string + "@mail.ru"
