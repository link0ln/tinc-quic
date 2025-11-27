## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = tincd tinc
check_PROGRAMS = sptps_test sptps_keypair
EXTRA_PROGRAMS = sptps_test sptps_keypair

CLEANFILES = version_git.h

.PHONY: version-stamp
version-stamp:

version_git.h: version-stamp
	$(AM_V_GEN)echo >$@
	@-(cd $(srcdir) && git describe 2>/dev/null >/dev/null) && echo '#define GIT_DESCRIPTION "'`(cd $(srcdir) && git describe) | sed 's/release-//'`'"' >$@ ||:
${srcdir}/version.c: version_git.h

## Now a hack to appease some versions of BSD make that don't understand that "./foo" is the same as "foo".
if BSD
version.c: ${srcdir}/version.c
endif

if LINUX
EXTRA_PROGRAMS += sptps_speed
endif

tincd_SOURCES = \
	address_cache.c address_cache.h \
	autoconnect.c autoconnect.h \
	buffer.c buffer.h \
	cert_autogen.c cert_autogen.h \
	conf.c conf.h \
	config_template.c config_template.h \
	connection.c connection.h \
	control.c control.h \
	control_common.h \
	crypto.h \
	device.h \
	dropin.c dropin.h \
	dummy_device.c \
	edge.c edge.h \
	ethernet.h \
	event.c event.h \
	fd_device.c \
	graph.c graph.h \
	hash.c hash.h \
	hosts_json.c hosts_json.h \
	ifconfig_auto.c ifconfig_auto.h \
	invitation.c invitation.h \
	have.h \
	ipv4.h \
	ipv6.h \
	list.c list.h \
	logger.c logger.h \
	meta.c meta.h \
	multicast_device.c \
	names.c names.h \
	net.c net.h \
	net_packet.c \
	net_setup.c \
	net_socket.c \
	netutl.c netutl.h \
	node.c node.h \
	process.c process.h \
	protocol.c protocol.h \
	protocol_auth.c \
	protocol_edge.c \
	protocol_invite.c \
	protocol_misc.c \
	protocol_subnet.c \
	quic.c quic.h \
	http3_frames.c http3_frames.h \
	padding.c padding.h \
	raw_socket_device.c \
	route.c route.h \
	script.c script.h \
	splay_tree.c splay_tree.h \
	subnet.c subnet.h \
	subnet_parse.c \
	system.h \
	tincd.c \
	utils.c utils.h \
	xalloc.h \
	version.c version.h

tinc_SOURCES = \
	config_template.c config_template.h \
	dropin.c dropin.h \
	fsck.c fsck.h \
	info.c info.h \
	list.c list.h \
	names.c names.h \
	netutl.c netutl.h \
	script.c script.h \
	subnet_parse.c subnet.h \
	tincctl.c tincctl.h \
	top.c top.h \
	utils.c utils.h \
	version.c version.h

# SPTPS tests removed

## Conditionally compile device drivers

if !GETOPT
tincd_SOURCES += \
	getopt.c getopt.h \
	getopt1.c
tinc_SOURCES += \
	getopt.c getopt.h \
	getopt1.c
endif

if LINUX
tincd_SOURCES += linux/device.c
endif

if BSD
tincd_SOURCES += bsd/device.c
if TUNEMU
tincd_SOURCES += bsd/tunemu.c bsd/tunemu.h
endif
endif

if SOLARIS
tincd_SOURCES += solaris/device.c
endif

if MINGW
tincd_SOURCES += mingw/device.c mingw/common.h
endif

if UML
tincd_SOURCES += uml_device.c
endif

if VDE
tincd_SOURCES += vde_device.c
endif

if OPENSSL
tincd_SOURCES += \
	openssl/crypto.c
tinc_SOURCES += \
	openssl/crypto.c
else
if GCRYPT
tincd_SOURCES += \
	gcrypt/crypto.c
tinc_SOURCES += \
	gcrypt/crypto.c
else
tincd_SOURCES += \
	nolegacy/crypto.c
tinc_SOURCES += \
	nolegacy/crypto.c
endif
endif

## Initialize variables first
tincd_LDADD =

if MINIUPNPC
tincd_SOURCES += upnp.h upnp.c
tincd_LDADD += $(MINIUPNPC_LIBS)
tincd_LDFLAGS = -pthread
endif

tinc_LDADD = $(READLINE_LIBS) $(CURSES_LIBS)
sptps_speed_LDADD = -lrt

LIBS = @LIBS@ -lm $(CODE_COVERAGE_LIBS)

if TUNEMU
LIBS += -lpcap
endif

## Define AM_CFLAGS before using +=
AM_CFLAGS = -DCONFDIR=\"$(sysconfdir)\" -DRUNSTATEDIR=\"$(runstatedir)\" -DLOCALSTATEDIR=\"$(localstatedir)\" -DSBINDIR=\"$(sbindir)\" -iquote. $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS)

if MSQUIC
tincd_LDADD += @MSQUIC_LIBS@
AM_CFLAGS += @MSQUIC_CFLAGS@
endif
