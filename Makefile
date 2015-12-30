PROJECT = sparkerl
PROJECT_DESCRIPTION = New project
PROJECT_VERSION = 0.0.1

DEPS = ranch lager erlsha2

dep_ranch = git https://github.com/ninenines/ranch.git 1.2.1
dep_lager = git https://github.com/basho/lager.git 3.0.2
dep_erlsha2 = git https://github.com/vinoski/erlsha2.git 2.2.1

include erlang.mk
