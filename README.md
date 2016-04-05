SparkErl
========

An Erlang implementation of the [Spark protocol](https://github.com/spark/spark-protocol) (eventually).



Generating your server keys
===========================

    openssl genrsa -out server-key.pem 2048
    openssl rsa -in server-key.pem -pubout > server-key.pub.pem

Getting your device keys
========================


Put your device into DFU mode, then use the particle cli to grab the key

    particle keys save keys/ID
