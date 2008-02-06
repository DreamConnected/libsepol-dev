############################ -*- Mode: Makefile -*- ###########################
## targets.mk ---
## Author           : Manoj Srivastava ( srivasta@glaurung.green-gryphon.com )
## Created On       : Sat Nov 15 01:10:05 2003
## Created On Node  : glaurung.green-gryphon.com
## Last Modified By : Manoj Srivastava
## Last Modified On : Tue Oct  9 01:50:58 2007
## Last Machine Used: anzu.internal.golden-gryphon.com
## Update Count     : 95
## Status           : Unknown, Use with caution!
## HISTORY          :
## Description      : The top level targets mandated by policy, as well as
##                    their dependencies.
##
## arch-tag: a81086a7-00f7-4355-ac56-8f38396935f4
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
##
###############################################################################

#######################################################################
#######################################################################
###############             Miscellaneous               ###############
#######################################################################
#######################################################################
source diff:
	@echo >&2 'source and diff are obsolete - use dpkg-source -b'; false

testroot:
	@test $$(id -u) = 0 || (echo need root priviledges; exit 1)

checkpo:
	$(CHECKPO)

# arch-buildpackage likes to call this
prebuild:

# OK. We have two sets of rules here, one for arch dependent packages,
# and one for arch independent packages. We have already calculated a
# list of each of these packages.

# In each set, we may need to do things in five steps: configure,
# build, install, package, and clean. Now, there can be a common
# actions to be taken for all the packages, all arch dependent
# packages, all all independent packages, and each package
# individually at each stage.

###########################################################################
# The current code does a number of things: It ensures that the highest   #
# dependency at any stage (usually the -Common target) depends on the	  #
# stamp-STAGE of the previous stage; so no work on a succeeding stage can #
# start before the previous stage is all done.				  #
###########################################################################

###########################################################################
# Next, all targets that have work performed in them do not have stamp	  #
# files on their own, and thus are not depended on directly by other	  #
# targets. Instead, they depend on and are depended up by intermediate	  #
# targets in which no work is done except to create stamp files. Other	  #
# targets just depend on the stamp files; so the build system does not do #
# work twice -- targets, which are up to date, are not executed again.    #
###########################################################################


#######################################################################
#######################################################################
###############             Configuration               ###############
#######################################################################
#######################################################################

# Work here
CONFIG-common:: testdir
	$(REASON)
	$(checkdir)

stamp-arch-conf:  CONFIG-common
	$(REASON)
	$(checkdir)
	@echo done > $@
stamp-indep-conf: CONFIG-common
	$(REASON)
	$(checkdir)
	@echo done > $@
STAMPS_TO_CLEAN += stamp-arch-conf stamp-indep-conf

# Work here
CONFIG-arch::  stamp-arch-conf
	$(REASON)
	$(checkdir)
CONFIG-indep:: stamp-indep-conf
	$(REASON)
	$(checkdir)

stamp-configure-arch:  CONFIG-arch
	$(REASON)
	@echo done > $@
stamp-configure-indep: CONFIG-indep
	$(REASON)
	@echo done > $@
STAMPS_TO_CLEAN += stamp-configure-arch stamp-configure-indep

# Work here
$(patsubst %,CONFIG/%,$(DEB_ARCH_PACKAGES))  :: CONFIG/% : stamp-configure-arch
	$(REASON)
	$(checkdir)
$(patsubst %,CONFIG/%,$(DEB_INDEP_PACKAGES)) :: CONFIG/% : stamp-configure-indep
	$(REASON)
	$(checkdir)

configure-arch-stamp: stamp-configure-arch  $(patsubst %,CONFIG/%,$(DEB_ARCH_PACKAGES))
	$(REASON)
	@echo done > $@
configure-indep-stamp: stamp-configure-indep $(patsubst %,CONFIG/%,$(DEB_INDEP_PACKAGES))
	$(REASON)
	@echo done > $@
STAMPS_TO_CLEAN += configure-arch-stamp configure-indep-stamp

# required
configure-arch:  configure-arch-stamp
	$(REASON)
configure-indep: configure-indep-stamp
	$(REASON)

stamp-configure: configure-arch configure-indep
	$(REASON)
	@echo done > $@

# required
configure: stamp-configure
	$(REASON)

STAMPS_TO_CLEAN += stamp-configure
#######################################################################
#######################################################################
###############                 Build                   ###############
#######################################################################
#######################################################################
# Work here
BUILD-common:: testdir stamp-configure
	$(REASON)
	$(checkdir)

stamp-arch-build:  BUILD-common
	$(REASON)
	$(checkdir)
	@echo done > $@
stamp-indep-build: BUILD-common
	$(REASON)
	$(checkdir)
	@echo done > $@
STAMPS_TO_CLEAN += stamp-arch-build stamp-indep-build

# sync. Work here
BUILD-arch::  stamp-arch-build
	$(REASON)
	$(checkdir)
BUILD-indep:: stamp-indep-build
	$(REASON)
	$(checkdir)

stamp-build-arch: BUILD-arch
	$(REASON)
	@echo done > $@
stamp-build-indep: BUILD-indep
	$(REASON)
	@echo done > $@
STAMPS_TO_CLEAN += stamp-build-arch stamp-build-indep

# Work here
$(patsubst %,BUILD/%,$(DEB_ARCH_PACKAGES))  :: BUILD/% : stamp-build-arch
	$(REASON)
	$(checkdir)
$(patsubst %,BUILD/%,$(DEB_INDEP_PACKAGES)) :: BUILD/% : stamp-build-indep
	$(REASON)
	$(checkdir)

build-arch-stamp: stamp-build-arch $(patsubst %,BUILD/%,$(DEB_ARCH_PACKAGES))
	$(REASON)
	@echo done > $@
build-indep-stamp: stamp-build-indep $(patsubst %,BUILD/%,$(DEB_INDEP_PACKAGES))
	$(REASON)
	@echo done > $@
STAMPS_TO_CLEAN += build-arch-stamp build-indep-stamp

# required
build-arch: build-arch-stamp
	$(REASON)
build-indep: build-indep-stamp
	$(REASON)

stamp-build: build-arch build-indep
	$(REASON)
	@echo done > $@

# required
build: stamp-build
	$(REASON)

STAMPS_TO_CLEAN += stamp-build

# Work here
POST-BUILD-arch-stamp:: build-arch-stamp
	$(REASON)
	@echo done > $@
STAMPS_TO_CLEAN += POST-BUILD-arch-stamp

POST-BUILD-indep-stamp:: build-indep-stamp
	$(REASON)
	@echo done > $@
STAMPS_TO_CLEAN += POST-BUILD-indep-stamp
#######################################################################
#######################################################################
###############                Install                  ###############
#######################################################################
#######################################################################
# Work here
INST-common:: testdir stamp-build POST-BUILD-arch-stamp POST-BUILD-indep-stamp
	$(checkdir)
	$(REASON)

stamp-arch-inst: INST-common
	$(REASON)
	$(checkdir)
	@echo done > $@
stamp-indep-inst: INST-common
	$(REASON)
	$(checkdir)
	@echo done > $@
STAMPS_TO_CLEAN += stamp-arch-inst stamp-indep-inst

# sync. Work here
INST-arch::  stamp-arch-inst
	$(REASON)
	$(checkdir)
INST-indep:: stamp-indep-inst
	$(REASON)
	$(checkdir)

stamp-install-arch:  INST-arch
	$(REASON)
	@echo done > $@
stamp-install-indep: INST-indep
	$(REASON)
	@echo done > $@
STAMPS_TO_CLEAN += stamp-install-arch stamp-install-indep

# Work here
$(patsubst %,INST/%,$(DEB_ARCH_PACKAGES))  :: INST/% : testroot stamp-install-arch
	$(REASON)
	$(checkdir)
$(patsubst %,INST/%,$(DEB_INDEP_PACKAGES)) :: INST/% : testroot stamp-install-indep
	$(REASON)
	$(checkdir)

install-arch-stamp: stamp-install-arch   $(patsubst %,INST/%,$(DEB_ARCH_PACKAGES))
	$(REASON)
	$(checkdir)
	@echo done > $@
install-indep-stamp: stamp-install-indep $(patsubst %,INST/%,$(DEB_INDEP_PACKAGES))
	$(REASON)
	$(checkdir)
	@echo done > $@
STAMPS_TO_CLEAN += install-arch-stamp install-indep-stamp

#required
install-arch: install-arch-stamp
	$(REASON)
install-indep: install-indep-stamp
	$(REASON)

stamp-install: install-indep install-arch
	$(REASON)
	@echo done > $@

#required
install: stamp-install
	$(REASON)

STAMPS_TO_CLEAN += stamp-install
#######################################################################
#######################################################################
###############                Package                  ###############
#######################################################################
#######################################################################
# Work here
BIN-common:: testdir testroot  stamp-install
	$(REASON)
	$(checkdir)

stamp-arch-bin:  testdir testroot BIN-common
	$(REASON)
	$(checkdir)
	@echo done > $@
stamp-indep-bin: testdir testroot BIN-common
	$(REASON)
	$(checkdir)
	@echo done > $@
STAMPS_TO_CLEAN += stamp-arch-bin stamp-indep-bin

# sync Work here
BIN-arch::  testroot stamp-arch-bin
	$(REASON)
	$(checkdir)
BIN-indep:: testroot stamp-indep-bin
	$(REASON)
	$(checkdir)

stamp-binary-arch:  BIN-arch
	$(REASON)
	@echo done > $@
stamp-binary-indep: BIN-indep
	$(REASON)
	@echo done > $@
STAMPS_TO_CLEAN += stamp-binary-arch stamp-binary-indep

# Work here
$(patsubst %,BIN/%,$(DEB_ARCH_PACKAGES))  :: BIN/% : testroot stamp-binary-arch
	$(REASON)
	$(checkdir)
$(patsubst %,BIN/%,$(DEB_INDEP_PACKAGES)) :: BIN/% : testroot stamp-binary-indep
	$(REASON)
	$(checkdir)

binary-arch-stamp: stamp-binary-arch   $(patsubst %,BIN/%,$(DEB_ARCH_PACKAGES))
	$(REASON)
	$(checkdir)
	@echo done > $@
binary-indep-stamp: stamp-binary-indep $(patsubst %,BIN/%,$(DEB_INDEP_PACKAGES))
	$(REASON)
	$(checkdir)
	@echo done > $@
STAMPS_TO_CLEAN += binary-arch-stamp binary-indep-stamp

# required
binary-arch: binary-arch-stamp
	$(REASON)
binary-indep: binary-indep-stamp
	$(REASON)

stamp-binary: binary-indep binary-arch
	$(REASON)
	@echo done > $@

# required
binary: stamp-binary
	$(REASON)
	@echo arch package   = $(DEB_ARCH_PACKAGES)
	@echo indep packages = $(DEB_INDEP_PACKAGES)

STAMPS_TO_CLEAN += stamp-binary
#######################################################################
#######################################################################
###############                 Clean                   ###############
#######################################################################
#######################################################################
# Work here
CLN-common:: testdir
	$(REASON)
	$(checkdir)

# sync Work here
CLN-arch::  CLN-common
	$(REASON)
	$(checkdir)
CLN-indep:: CLN-common
	$(REASON)
	$(checkdir)
# Work here
$(patsubst %,CLEAN/%,$(DEB_ARCH_PACKAGES))  :: CLEAN/% : CLN-arch
	$(REASON)
	$(checkdir)
$(patsubst %,CLEAN/%,$(DEB_INDEP_PACKAGES)) :: CLEAN/% : CLN-indep
	$(REASON)
	$(checkdir)

clean-arch: CLN-arch $(patsubst %,CLEAN/%,$(DEB_ARCH_PACKAGES))
	$(REASON)
clean-indep: CLN-indep $(patsubst %,CLEAN/%,$(DEB_INDEP_PACKAGES))
	$(REASON)

stamp-clean: clean-indep clean-arch
	$(REASON)
	$(checkdir)
	-test -f Makefile && $(MAKE) distclean
	-rm -f  $(FILES_TO_CLEAN) $(STAMPS_TO_CLEAN)
	-rm -rf $(DIRS_TO_CLEAN)
	-rm -f core TAGS                                                     \
               `find . ! -regex '.*/\.git/.*' ! -regex '.*/\{arch\}/.*'      \
                       ! -regex '.*/CVS/.*'   ! -regex '.*/\.arch-ids/.*'    \
                       ! -regex '.*/\.svn/.*'                                \
                   \( -name '*.orig' -o -name '*.rej' -o -name '*~'       -o \
                      -name '*.bak'  -o -name '#*#'   -o -name '.*.orig'  -o \
		      -name '.*.rej' -o -name '.SUMS' \)                     \
                -print`

clean: stamp-clean
	$(REASON)


#######################################################################
#######################################################################
###############                                         ###############
#######################################################################
#######################################################################

.PHONY: CONFIG-common  CONFIG-indep  CONFIG-arch  configure-arch  configure-indep  configure     \
        BUILD-common   BUILD-indep   BUILD-arch   build-arch      build-indep      build         \
        INST-common    INST-indep    INST-arch    install-arch    install-indep    install       \
        BIN-common     BIN-indep     BIN-arch     binary-arch     binary-indep     binary        \
        CLN-common     CLN-indep     CLN-arch     clean-arch      clean-indep      clean         \
        $(patsubst %,CONFIG/%,$(DEB_INDEP_PACKAGES)) $(patsubst %,CONFIG/%,$(DEB_ARCH_PACKAGES)) \
        $(patsubst %,BUILD/%, $(DEB_INDEP_PACKAGES)) $(patsubst %,BUILD/%, $(DEB_ARCH_PACKAGES)) \
        $(patsubst %,INST/%,  $(DEB_INDEP_PACKAGES)) $(patsubst %,INST/%,  $(DEB_ARCH_PACKAGES)) \
        $(patsubst %,BIN/%,   $(DEB_INDEP_PACKAGES)) $(patsubst %,BIN/%,   $(DEB_ARCH_PACKAGES)) \
        $(patsubst %,CLEAN/%, $(DEB_INDEP_PACKAGES)) $(patsubst %,CLEAN/%, $(DEB_ARCH_PACKAGES)) \
        implode explode prebuild checkpo

#Local variables:
#mode: makefile
#End:
