PROJECT = sparkerl
PROJECT_DESCRIPTION = New project
PROJECT_VERSION = 0.0.1

DEPS = ranch lager gen_coap

dep_ranch = git https://github.com/ninenines/ranch.git 1.2.1
dep_lager = git https://github.com/basho/lager.git 3.0.2
dep_gen_coap = git https://github.com/gotthardp/gen_coap.git v0.1.0

include erlang.mk
