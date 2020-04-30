targets = all clean distclean install

.PHONY: $(targets)
$(targets):
	$(MAKE) -C common $@
	$(MAKE) -C quote_dump $@
	$(MAKE) -C voting_enclave $@
	$(MAKE) -C verify_ias_report $@
