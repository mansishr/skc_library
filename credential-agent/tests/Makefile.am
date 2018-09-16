bindir = $(prefix)/test
bin_SCRIPTS = test_cred_agent.sh

install-exec-hook:
	$(SED) -i "s|__PREFIX__|@prefix@|" $(DESTDIR)$(bindir)/test_cred_agent.sh
