bindir=$(prefix)/bin
commondir=$(prefix)/bin/credential-agent
datadir=$(prefix)/etc

bin_SCRIPTS = credential_agent_tool credential_agent_init
common_SCRIPTS = common_utils
data_DATA = credential_agent.ini

install-exec-hook:
	@echo "calling install-exec-hook"
	$(SED) -i "s|__PREFIX__|@prefix@|" $(DESTDIR)$(bindir)/credential_agent_tool
	$(SED) -i "s|__PREFIX__|@prefix@|" $(DESTDIR)$(bindir)/credential_agent_init
install-data-hook:
	@echo "calling install-data-hook"
	$(SED) -i "s|__PREFIX__|@prefix@|" $(DESTDIR)$(datadir)/credential_agent.ini

#$(SED) -i "s|__PREFIX__|@prefix@|" $(DESTDIR)$(commondir)/common_utils


