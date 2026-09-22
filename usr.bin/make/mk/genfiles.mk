# $Id: genfiles.mk,v 1.6 2026/07/15 21:37:18 sjg Exp $
#
#	@(#) Copyright (c) 2024-2026, Simon J. Gerraty
#
#	SPDX-License-Identifier: BSD-2-Clause
#
#	Please send copies of changes and bug-fixes to:
#	sjg@crufty.net
#

# Pipe the sources though egrep -v if EXCLUDES.${.TARGET} is defined
# and/or sed if SED_CMDS.${.TARGET} is defined
# Note: this works best in meta mode as any change to EXCLUDES or
# SED_CMDS will make the target out-of-date.
# Finally; run chmod if MODE.${TARGET} is set
_GENFILES_USE:	.USE
	@cat ${SRCS.${.TARGET}:U${.ALLSRC:u}} \
	${EXCLUDES.${.TARGET}:D| ${EGREP:Uegrep} -v '${EXCLUDS.${.TARGET}:ts|}'} \
	${SED_CMDS.${.TARGET}:D| ${SED:Used} ${SED_CMDS.${.TARGET}}} \
	${FILTER.${.TARGET}:D| ${FILTER.${.TARGET}}} \
	> ${.TARGET}
	@${MODE.${.TARGET}:D${CHMOD:Uchmod} ${MODE.${.TARGET}} ${.TARGET}}
