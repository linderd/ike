#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko
import os

import rsa
from subprocess import call

VerifyError = rsa.VerificationError

# TODO: add Rainbow here


def sign(data, filename, hash_alg="SHA-256"):
    assert isinstance(data, bytes)
    with open(filename, 'rb') as keyfile:
        private_key = rsa.PrivateKey.load_pkcs1(keyfile.read())
    return rsa.sign(data, private_key, hash_alg)


def verify(data, signature, filename):
    with open(filename, 'rb') as publicfile:
        public_key = rsa.PublicKey.load_pkcs1(publicfile.read())
    try:
        return rsa.verify(data, signature, public_key)
    except rsa.VerificationError:
        raise


def sign_rainbow(data, usk_filename):
    assert isinstance(data, bytes)
    # This should be done with pipes, but I don't have the time
    with open('data.txt', 'wb') as data_file:
        data_file.write(data)
    call(["/id_rainbow/rainbow-sign", usk_filename, "data.txt", " | tee signature.txt"])
    os.remove('data.txt')
    with open('signature.txt', 'rb') as signature:
        return signature


def verify_rainbow(data, signature, upk_filename):
    with open('data.txt', 'wb') as data_file:
        data_file.write(data)
    with open('signature.txt', 'wb') as signature_file:
        signature_file.write(signature)
    call(["/id_rainbow/rainbow-verify", upk_filename, "signature.txt", "data.txt", " | tee verification.txt"])
    with open('verification.txt', 'r') as verification:
        if verification[-1] == 0:
            return 0
        else:
            raise
