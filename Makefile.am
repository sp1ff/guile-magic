SUBDIRS = magic test

ACLOCAL_AMFLAGS = -I build-aux

# Surprisingly, Automake does not support Guile projects by default. Guile ships with a set of
# Autoconf macros (guile.m4), but we need to write our own Automake rules for compiling and
# installing them.
moddir = $(_MAGIC_GUILE_SITE)

ccachedir = $(_MAGIC_GUILE_CCACHE)

SOURCES = magic.scm

EXTRA_DIST = $(SOURCES)

GOBJECTS = $(SOURCES:%.scm=%.go)

# Per the Automake manual \"If make built it, and it is commonly something that one would want to 
# rebuild (for instance, a .o file), then mostlyclean should delete it.\"-- that's why I put the 
# `.go' objects here.
MOSTLYCLEANFILES = $(GOBJECTS)

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

.scm.go:
	$(AM_V_GEN)$(GUILD) compile -L $(srcdir) -L $(abs_top_builddir) $(GUILD_WARNINGS) -o "$@" "$<"
