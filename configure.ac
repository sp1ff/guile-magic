AC_INIT([guile-magic], [1.0.0], [sp1ff@pobox.com], [guile-magic], [https://github.com/sp1ff/guile-magic])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([build-aux])
AC_CONFIG_SRCDIR([magic/magic.scm])

AM_INIT_AUTOMAKE([-Wall -Werror gnits std-options dist-bzip2 dist-xz])

AC_CHECK_LIB([magic], [magic_version], [],
  [AC_MSG_ERROR([Unable to find libmagic; check your package manager for `libmagic-dev'])])

GUILE_PKG([3.0 2.2])
GUILE_PROGS
GUILE_SITE_DIR

dnl This logic decides where Scheme modules go. The GUILE_SITE_DIR
dnl call, above, retrieves the location as recorded by `pkgconfig',
dnl but that's not appropriate for an installation to a non-standard
dnl place via the --prefix option. The rules are as follows:
dnl   1. if ${MAGIC_GUILE_SITE} is non-empty, use that
dnl   2. if ${prefix} is "NONE"
dnl      - if GUILE_SITE is not empty, use GUILE_SITE
dnl      - use ${ac_default_prefix}/share/guile/site
dnl   3. use ${prefix}/share/guile/site

AC_ARG_VAR([MAGIC_GUILE_SITE], [The directory under which Scheme modules
shall be installed.  Unset or empty means install into
${datadir}/guile/site.])

if test -n "${MAGIC_GUILE_SITE}"; then
    _MAGIC_GUILE_SITE="${MAGIC_GUILE_SITE}"
elif test "${prefix}" == "NONE"; then
    if test -n "${GUILE_SITE}"; then
        _MAGIC_GUILE_SITE="${GUILE_SITE}"
    else
        _MAGIC_GUILE_SITE="${ac_default_prefix}/share/guile/site"
    fi
else
    _MAGIC_GUILE_SITE="${prefix}/share/guile/site"
fi

AC_MSG_NOTICE([Scheme modules will be installed under ${_MAGIC_GUILE_SITE}])
AC_SUBST([_MAGIC_GUILE_SITE])

dnl This logic decides where compiled Schmee files (`.go' files) shall be installed.
dnl The rules are as follows:
dnl   1. if ${MAGIC_SITE_CCACHE} is non-empty, use that
dnl   2. if ${prefix} is "NONE"
dnl      - if GUILE_SITE_CCACHE is not empty, use GUILE_SITE_CCACHE
dnl      - use ${ac_default_prefix}/lib/guile/${GUILE_EFFECTIVE_VERSION}/site-ccache
dnl   3. use ${prefix}/lib/guile/${GUILE_EFFECTIVE_VERSION}/site-ccache

AC_ARG_VAR([MAGIC_GUILE_CCACHE], [The directory under which compiled Scheme
files shall be installed.  Unset or empty means install into
$(libdir)/guile/$GUILE_EFFECTIVE_VERSION/site-ccache.])

if test -n "${MAGIC_GUILE_CCACHE}"; then
    _MAGIC_GUILE_CCACHE="${MAGIC_GUILE_CCACHE}"
elif test "${prefix}" == "NONE"; then
    if test -n "${GUILE_SITE_CCACHE}"; then
        _MAGIC_GUILE_CCACHE="${GUILE_SITE_CCACHE}"
    else
        _MAGIC_GUILE_CCACHE="${ac_default_prefix}/lib/guile/${GUILE_EFFECTIVE_VERSION}/site-ccache"
    fi
else
    _MAGIC_GUILE_CCACHE="${prefix}/lib/guile/${GUILE_EFFECTIVE_VERSION}/site-ccache"
fi

AC_MSG_NOTICE([Compiled Scheme files will be installed under ${_MAGIC_GUILE_CCACHE}])
AC_SUBST([_MAGIC_GUILE_CCACHE])    

AC_CONFIG_FILES([Makefile magic/Makefile magic/vars.scm.am test/Makefile test/data/Makefile])

AC_OUTPUT
