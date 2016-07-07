################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC example programs
################################################################################

exportdir = $(docdir)/export

noinst_LTLIBRARIES = librohc_compressor_module.la

librohc_compressor_module_la_CXXFLAGS = \
	$(configure_cflags) 
librohc_compressor_module_la_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp
librohc_compressor_module_la_LDFLAGS = \
	$(configure_ldflags)
librohc_compressor_module_la_SOURCES = \
	rohc_compressor_module.cpp \
	rohc_decompressor_module.cpp
librohc_compressor_module_la_LIBADD = \
	$(top_builddir)/src/librohc.la \
	$(additional_platform_libs)

pkginclude_HEADERS = rohc_decompressor_module.h rohc_compressor_module.h

