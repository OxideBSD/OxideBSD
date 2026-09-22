# $Id: top.mk,v 1.2 2026/07/30 17:45:17 sjg Exp $
#
#	@(#) Copyright (c) 2026, Simon J. Gerraty
#
#	SPDX-License-Identifier: BSD-2-Clause
#
#	Please send copies of changes and bug-fixes to:
#	sjg@crufty.net
#

# This makefile is used by top-level makefile
# or indeed used to replace it:
#
#	.if ${.MAKE.LEVEL} == 0 && ${.CURDIR} == ${SRCTOP}
#	.MAKE.MAKEFILE_PREFERENCE = top.mk
#	.endif
#
_CURDIR ?= ${.CURDIR}
.if ${.MAKE.LEVEL} == 0 && ${_CURDIR} == ${SRCTOP}
.if make(*-jobs)
.include <jobs.mk>
.else
.if ${.MAKE.MAKEFILE_PREFERENCE:U:M*top.mk} != ""
# Remove ourselves now
.MAKE.MAKEFILE_PREFERENCE := ${.MAKE.MAKEFILE_PREFERENCE:N*top.mk}
.endif
.if ${MK_DIRDEPS_BUILD:Uno} == "yes"
.include <dirdeps-targets.mk>
.endif
.-include <local.top.mk>
.endif
.endif

