
COLOR 3f
SET ERL_LIBS=%CD%\deps

erl -pa ./ebin -boot start_sasl -s dns_proxy