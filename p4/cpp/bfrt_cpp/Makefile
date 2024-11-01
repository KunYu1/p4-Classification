#
# A simple Makefile for a program and its BfRt Control Plane
#
ifndef SDE_INSTALL
$(error SDE_INSTALL is not set)
endif


EXE_FILE = bfrt_cp




#
# C++ Compilation stuff
#
CC=g++
CPPFLAGS = -I$(SDE_INSTALL)/include \
		   -DSDE_INSTALL=\"$(SDE_INSTALL)\" \
           -DPROG_NAME=\"$(PROG)\" \
		   -I $(SDE)/pkgsrc/bf-drivers/include \
		   -I $(SDE)/pkgsrc/bf-drivers/src/bf_rt
CXXFLAGS = -g -std=c++17 -Wall -Wextra -MMD -MF $@.d
BF_LIBS  = -L$(SDE_INSTALL)/lib -lbfutils -ldriver
LDLIBS   = -lm -ldl -lpthread -lpcap

LDFLAGS  = -Wl,-rpath,$(SDE_INSTALL)/lib

DEPS := $(OBJS:.o=.o.d)


all: bfrt_cpp main_cpp ipc_cpp
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(BF_LIBS) $(LDFLAGS) -o $(EXE_FILE) src/obj/ipc.o src/obj/bfrt.o src/obj/main.o $(LDLIBS) 
	@echo Build Success!

main_cpp: src/main.cpp
	mkdir -p src/obj
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(BF_LIBS) $(LDLIBS) $(LDFLAGS) -c src/main.cpp -o src/obj/main.o

bfrt_cpp: src/bfrt.cpp
	mkdir -p src/obj
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(BF_LIBS) $(LDLIBS) $(LDFLAGS) -c src/bfrt.cpp -o src/obj/bfrt.o

ipc_cpp: ../ipc/IPC.cpp
	mkdir -p src/obj
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(TF_LIBS) $(LDLIBS) $(LDFLAGS) -c ../ipc/IPC.cpp -o src/obj/ipc.o


clean:
	-@rm -rf $(PROG) *~ *.o *.d *.tofino *.tofino2 zlog-cfg-cur bf_drivers.log.* *_cp
	-@rm -rf bfrt_c++/obj/*
