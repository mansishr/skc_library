bindir=$(prefix)/bin
commondir=$(prefix)/bin/credential-agent

bin_SCRIPTS = credential_agent_tool credential_agent_init
common_SCRIPTS = common_utils

install-exec-hook:
	@echo "calling install-exec-hook"
	$(SED) -i "s|__PREFIX__|@prefix@|" $(DESTDIR)$(bindir)/credential_agent_tool
	$(SED) -i "s|__PREFIX__|@prefix@|" $(DESTDIR)$(bindir)/credential_agent_init


