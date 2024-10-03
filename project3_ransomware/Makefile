.PHONY: all install clean

all: install

install: crack_attacker attacker_server

crack_attacker: crack_attacker.py
	@cp $< $@
	@echo '#!/usr/bin/env python3' > $@
	@cat $< >> $@
	@chmod +x $@

attacker_server: attacker_server.py
	@cp $< $@
	@echo '#!/usr/bin/env python3' > $@
	@cat $< >> $@
	@chmod +x $@

clean:
	@rm -f crack_attacker attacker_server
