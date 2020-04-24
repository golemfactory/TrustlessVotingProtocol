targets = all clean distclean install

.PHONY: $(targets)
$(targets):
	$(MAKE) -C common $@
	$(MAKE) -C voting_enclave $@
