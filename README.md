SparkErl
========

An Erlang implementation of the [Spark protocol](https://github.com/spark/spark-protocol) (eventually).



Generating your keys
====================

    openssl genrsa -out server-key.pem 2048
    openssl rsa -in server-key.pem -pubout > server-key.pub.pem

