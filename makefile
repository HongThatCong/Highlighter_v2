PROC=highlighter

include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)highlighter2$(O): \
    $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp  \
    $(I)dbg.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp            \
    $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp       \
    $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp                   \
    $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp     \
    $(I)ua.hpp $(I)xref.hpp highlighter.cpp
