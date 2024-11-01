#
# A simple Makefile for a program and its BfRt Control Plane
#
#ifndef SDE_INSTALL
#$(error SDE_INSTALL is not set)
#endif


P4_FILE = p4src/appClassification.p4


#
# Final targets
#
all: reset_nic
	PATH=$(SDE_INSTALL)/bin:$$PATH \
	LD_LIBRARY_PATH=/usr/local/lib:$$SDE_INSTALL/lib:$$LD_LIBRARY_PATH \
	./bfrt_cp

p4:
	$(SDE)/p4_build.sh $(P4_FILE)

p4rt_cpp:
	@make -C cpp/p4rt_cpp
	@cp cpp/p4rt_cpp/p4rt_exe .

tf_cpp:
	@make -C cpp/tf_cpp
	@cp cpp/tf_cpp/tf_cp .


clean:
	-@rm -rf $(PROG) *~ *.o *.d *.tofino *.tofino2 zlog-cfg-cur bf_drivers.log.* *_cp
	-@rm -rf p4rt_exe
	-@rm -rf tf_cp
