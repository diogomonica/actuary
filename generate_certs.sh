#!/bin/bash

openssl req -newkey rsa:2048 -nodes -keyout domain.key -x509 -days 365 -out domain.crt -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=Actuary'
