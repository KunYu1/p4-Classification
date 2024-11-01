P4RT_ROOT = p4rt/p4/v1
P4RT_CONFIG_ROOT = p4rt/p4/config/v1
P4RT_CC = ${P4RT_ROOT}/p4runtime.grpc.pb.cc ${P4RT_ROOT}/p4runtime.pb.cc ${P4RT_ROOT}/p4data.grpc.pb.cc ${P4RT_ROOT}/p4data.pb.cc
P4RT_O = p4runtime.grpc.pb.o p4runtime.pb.o p4data.grpc.pb.o p4data.pb.o
P4RT_CONFIG_CC =  ${P4RT_CONFIG_ROOT}/p4info.grpc.pb.cc ${P4RT_CONFIG_ROOT}/p4info.pb.cc ${P4RT_CONFIG_ROOT}/p4types.pb.cc ${P4RT_CONFIG_ROOT}/p4types.grpc.pb.cc
P4RT_CONFIG_O =  p4info.grpc.pb.o p4info.pb.o p4types.pb.o p4types.grpc.pb.o
GOOGLE_RPC_CC = p4rt/google/rpc/status.pb.cc
GOOGLE_RPC_O = status.pb.o

# Add ipc.o to the list of object files
IPC_CPP = ../ipc/IPC.cpp
IPC_O = src/obj/ipc.o

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

all: p4rt.cpp ${IPC_O}
	g++ -g p4rt.cpp ${P4RT_O} ${P4RT_CONFIG_O} ${GOOGLE_RPC_O} ${IPC_O} -Ip4rt -lprotobuf -lgrpc++ -lpcap -o p4rt_exe

# Compile ipc.o
${IPC_O}: ${IPC_CPP}
	mkdir -p src/obj
	$(CC) $(CPPFLAGS) $(CXXFLAGS) -c ${IPC_CPP} -o ${IPC_O}
