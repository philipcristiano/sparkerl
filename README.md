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


Implement a handler
===================

Handlers operate within their own process as part of the protocol FSM. The
handler will allow you to handle API calls from the microcontroller. Eventually
will be a behaviour, look at `src/sparkerl_handler` for now.

The handler needs to be configured via the `protocol_handler` key in the
`sparkerl` application.
