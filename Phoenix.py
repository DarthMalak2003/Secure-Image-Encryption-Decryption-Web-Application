from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from PIL import Image
import os
import pickle
import cv2
import tensorflow as tf
from tensorflow import keras
import numpy as np

path = "/Users/aviral/Documents/JIIT/5th Semester/Information Security Lab/Project/IS WEB APP/static/original"

key1 = 15
key2 = 17
global k1
global k2
k2 = 0
app = Flask(__name__)


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "file" in request.files:
        file = request.files["file"]
        filename = secure_filename(file.filename)
        if os.path.isfile(path):
            os.remove(path)
        file.save(path)

        def prime(x, y):
            prime_list = []
            for i in range(x, y):
                if i == 0 or i == 1:
                    continue
                else:
                    for j in range(2, int(i / 2) + 1):
                        if i % j == 0:
                            break
                    else:
                        prime_list.append(i)
            return prime_list

        # Driver program
        starting_range = 2
        ending_range = 255
        lst = prime(starting_range, ending_range)

        from numpy import random

        randomprime = random.choice(lst)

        print(randomprime)

        # Python3 program to find primitive root
        # of a given number n
        from math import sqrt

        # Returns True if n is prime
        def isPrime(n):
            # Corner cases
            if n <= 1:
                return False
            if n <= 3:
                return True

            # This is checked so that we can skip
            # middle five numbers in below loop
            if n % 2 == 0 or n % 3 == 0:
                return False
            i = 5
            while i * i <= n:
                if n % i == 0 or n % (i + 2) == 0:
                    return False
                i = i + 6

            return True

        """ Iterative Function to calculate (x^n)%p
            in O(logy) */"""

        def power(x, y, p):
            res = 1  # Initialize result

            x = x % p  # Update x if it is more
            # than or equal to p

            while y > 0:
                # If y is odd, multiply x with result
                if y & 1:
                    res = (res * x) % p

                # y must be even now
                y = y >> 1  # y = y/2
                x = (x * x) % p

            return res

        # Utility function to store prime
        # factors of a number
        def findPrimefactors(s, n):
            # Print the number of 2s that divide n
            while n % 2 == 0:
                s.add(2)
                n = n // 2

            # n must be odd at this point. So we can
            # skip one element (Note i = i +2)
            for i in range(3, int(sqrt(n)), 2):
                # While i divides n, print i and divide n
                while n % i == 0:
                    s.add(i)
                    n = n // i

            # This condition is to handle the case
            # when n is a prime number greater than 2
            if n > 2:
                s.add(n)

        # Function to find smallest primitive
        # root of n
        def findPrimitive(n):
            s = set()

            # Check if n is prime or not
            if isPrime(n) == False:
                return -1

            # Find value of Euler Totient function
            # of n. Since n is a prime number, the
            # value of Euler Totient function is n-1
            # as there are n-1 relatively prime numbers.
            phi = n - 1

            # Find prime factors of phi and store in a set
            findPrimefactors(s, phi)

            # Check for every number from 2 to phi
            for r in range(2, phi + 1):
                # Iterate through all prime factors of phi.
                # and check if we found a power with value 1
                flag = False
                for it in s:
                    # Check if r^((phi)/primefactors)
                    # mod n is 1 or not
                    if power(r, phi // it, n) == 1:
                        flag = True
                        break

                # If there was no power with value 1.
                if flag == False:
                    return r

            # If no primitive root found
            return -1

        # Driver Code
        n = randomprime
        y = findPrimitive(n)

        # print(n, " ", y)

        # Diffie-Hellman Code
        """P = randomprime
        G = y"""

        def prime_checker(p):
            # Checks If the number entered is a Prime Number or not
            if p < 1:
                return -1
            elif p > 1:
                if p == 2:
                    return 1
                for i in range(2, p):
                    if p % i == 0:
                        return -1
                    return 1

        def primitive_check(g, p, L):
            # Checks If The Entered Number Is A Primitive Root Or Not
            for i in range(1, p):
                L.append(pow(g, i) % p)
            for i in range(1, p):
                if L.count(i) > 1:
                    L.clear()
                    return -1
                return 1

        l = []
        while 1:
            P = int(randomprime)
            if prime_checker(P) == -1:
                print("Number Is Not Prime, Please Enter Again!")
                continue
            break

        while 1:
            G = int(y)
            if primitive_check(G, P, l) == -1:
                print(f"Number Is Not A Primitive Root Of {P}, Please Try Again!")
                continue
            break

        # Private Keys
        x1, x2 = key1, key2
        # while 1:
        #     if x1 >= P or x2 >= P:
        #         print(f"Private Key Of Both The Users Should Be Less Than {P}!")
        #         continue
        #     break

        # Calculate Public Keys
        y1, y2 = pow(G, x1) % P, pow(G, x2) % P

        # Generate Secret Keys
        k1, k2 = pow(y2, x1) % P, pow(y1, x2) % P

        # print(f"\nSecret Key For User 1 Is {k1}\nSecret Key For User 2 Is {k2}\n")

        # if k1 == k2:
        #     print("Keys Have Been Exchanged Successfully")
        # else:
        #     print("Keys Have Not Been Exchanged Successfully")
        def encrypt():
            # path = "/Users/aviral/Documents/JIIT/5th Semester/Information Security Lab/Project/IS WEB APP/static/original.jpeg"

            # taking encryption key as input
            # key = int(input('Enter Key for encryption of Image : '))
            key = k1
            # print path of image file and encryption key that
            # we are using
            # print('The path of file : ', path)
            # print('Key for encryption : ', key)

            # open file for reading purpose
            fin = open(path, "rb")

            # storing image data in variable "img"
            img = fin.read()
            fin.close()

            # converting image into byte array to
            # perform encryption easily on numeric data
            img = bytearray(img)

            # performing XOR operation on each value of bytearray
            for index, values in enumerate(img):
                img[index] = values ^ key
            # opening file for writing purpose
            fin = open(
                "/Users/aviral/Documents/JIIT/5th Semester/Information Security Lab/Project/IS WEB APP/static/encrypted",
                "wb",
            )

            # writing encrypted data in image
            fin.write(img)
            fin.close()

            f = open("demofile2.txt", "w")
            f.write(str(k2))
            f.close()
            # print('Encryption Done...')

    # key1 = int(request.form.get("key1"))
    encrypt()
    return render_template("home.html")


@app.route("/download")
def download():
    def decrypt():
        path = "/Users/aviral/Documents/JIIT/5th Semester/Information Security Lab/Project/IS WEB APP/static/encrypted"
        f = open("demofile2.txt", "r")
        k2 = f.read()
        # taking encryption key as input
        # key = int(input('Enter Key for decryption of Image : '))
        key = int(k2)
        # print path of image file and encryption key that
        # we are using
        # print('The path of file : ', path)
        # print('Key for encryption : ', key)

        # open file for reading purpose
        fin = open(path, "rb")

        # storing image data in variable "img"
        img = fin.read()
        fin.close()

        # converting image into byte array to
        # perform encryption easily on numeric data
        img = bytearray(img)

        # performing XOR operation on each value of bytearray
        for index, values in enumerate(img):
            img[index] = values ^ key
        # opening file for writing purpose
        fin = open(
            "/Users/aviral/Documents/JIIT/5th Semester/Information Security Lab/Project/IS WEB APP/static/decrypted",
            "wb",
        )

        # writing encrypted data in image
        fin.write(img)
        fin.close()
        # print('Decryption Done...')

    decrypt()
    return render_template("result.html")


@app.route("/check", methods=["POST"])
def check():
    uname = request.form.get("username")
    pword = request.form.get("password")
    select = request.form.get("select")
    if (uname == "user1" and pword == "user1") or (
        uname == "user2" and pword == "user2"
    ):
        if str(select) == "Upload":
            return render_template("upload.html")
        else:
            return render_template("download.html")


app.run("localhost", 3000)
