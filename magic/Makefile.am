# `vars.scm.am.in` contains Installation Directory Variables
# <https://www.gnu.org/software/autoconf/manual/autoconf-2.67/html_node/Installation-Directory-Variables.html#Installation-Directory-Variables>
# So, e.g. @sysconfdir@ will be replaced with ${prefix}/etc by
# Autoconf. This is so we can produce Makefiles that comply with the
# GCS in that the user can still change the installation location at
# make-time.

# I handle this by having Autconf process vars.scm.am.in to
# vars.scm.am at configure time, and adding a rule to Automake to
# build vars.scm from vars.scm.am at make-time.
$(abs_top_builddir)/magic/vars.scm: vars.scm.am
	sed -e "s|\$${prefix}|$(prefix)|g" $< > $@

# Surprisingly, Automake does not support Guile projects by default. Guile ships with a set of
# Autoconf macros (guile.m4), but we need to write our own Automake rules for compiling and
# installing them.
moddir = $(_MAGIC_GUILE_SITE)/magic

ccachedir = $(_MAGIC_GUILE_CCACHE)/magic

SOURCES = magic.scm $(builddir)/vars.scm

EXTRA_DIST = $(SOURCES)

GOBJECTS = $(SOURCES:%.scm=%.go)

# Per the Automake manual \"If make built it, and it is commonly something that one would want to 
# rebuild (for instance, a .o file), then mostlyclean should delete it.\"-- that's why I put the 
# `.go' objects here.
MOSTLYCLEANFILES = $(GOBJECTS) $(abs_top_builddir)/magic/vars.scm

mod_DATA = $(SOURCES)

ccache_DATA = $(GOBJECTS)

# Here https://lists.gnu.org/archive/html/guile-devel/2010-07/msg00125.html is the famous e-mail
# (I've seen this one e-mail message cited in multiple Guile projects at which I've looked) explaining
# how to install the script first, and then their compiled `.go' counterparts, so that the compiled
# versions will have a later timestamp.
guile_install_go_files = install-ccacheDATA

$(guile_install_go_files): install-modDATA

GUILD_WARNINGS = -Wunbound-variable -Warity-mismatch -Wformat

SUFFIXES = .scm .go

magic.go: magic.scm  $(abs_top_builddir)/magic/vars.scm
	$(AM_V_GEN)$(GUILD) compile -L $(srcdir)/.. -L $(abs_top_builddir) $(GUILD_WARNINGS) -o "$@" "$<"

$(builddir)/vars.go: vars.scm
	$(AM_V_GEN)$(GUILD) compile -L $(srcdir)/.. -L $(abs_top_builddir) $(GUILD_WARNINGS) -o "$@" "$<"

$(srcdir)/vars.scm: $(builddir)/vars.scm
	cp -v $(builddir)/magic/vars.scm $(srcdir)/magic/vars.scm
