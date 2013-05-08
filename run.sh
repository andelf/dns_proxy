#!/bin/bash

ERL_LIBS=`pwd`/deps sudo -E erl -pa ./ebin -boot start_sasl -s dns_proxy -sname dns -setcookie andelf
