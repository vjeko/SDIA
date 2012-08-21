include ../../Make.vars 

CONFIGURE_DEPENCIES = $(srcdir)/Makefile.am

SWITCH_LIB_VERSION = 1:0:0

EXTRA_DIST =                                    \
    meta.json

pkglib_LTLIBRARIES =                            \
    graph.la    

graph_la_CPPFLAGS =                            \
    $(AM_CPPFLAGS)                              \
    $(TBB_CPPFLAGS)                             \
    -I$(top_srcdir)/src/coreapps                \
    -I/usr/include/thrift

graph_la_SOURCES =                             \
    graph.cc protobuf/interface.pb.cc

graph_la_LDFLAGS =                             \
    $(AM_LDFLAGS) -export-dynamic -module       \
    -version-info $(SWITCH_LIB_VERSION)

graph_la_LIBADD =                              \
    $(TBB_LDFLAGS)                              \
    $(TBB_LIBS)                                 \
    -lboost_thread -lthrift -lprotobuf

NOX_RUNTIMEFILES = meta.json

all-local: nox-all-local
clean-local: nox-clean-local 
install-exec-hook: nox-install-local
