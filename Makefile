PROJECT = sparkerl
PROJECT_DESCRIPTION = New project
PROJECT_VERSION = 0.0.1

DEPS = ranch lager gen_coap pkcs7

dep_ranch = git https://github.com/ninenines/ranch.git 1.2.1
dep_lager = git https://github.com/basho/lager.git 3.0.2
dep_gen_coap = git https://github.com/gotthardp/gen_coap.git v0.1.0
dep_pkcs7 = git https://github.com/camshaft/pkcs7.erl.git 1.0.1

include erlang.mk
