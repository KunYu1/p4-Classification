

TF_PATH = /usr/local/
EXE_FILE = tf_cp

#
# C++ Compilation stuff
#
CC=g++
CPPFLAGS = -I $(TF_PATH)/include
CXXFLAGS = -g -std=c++17 -Wall -Wextra -MMD -MF $@.d
TF_LIBS  = -L$(TF_PATH)/lib -ltensorflow -fuse-ld=gold
LDLIBS   = -lm -ldl -lpthread -lpcap

LDFLAGS  = -Wl,-rpath,$(SDE_INSTALL)/lib

DEPS := $(OBJS:.o=.o.d)


all: hybridModel_cpp standardScaler_cpp ipc_cpp main_cpp
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(TF_LIBS) $(LDLIBS) $(LDFLAGS) -o $(EXE_FILE) src/obj/hybridModel.o src/obj/standardScaler.o src/obj/ipc.o src/obj/main.o
	@echo Build Success!


csv: hybridModel_cpp standardScaler_cpp ipc_cpp
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(TF_LIBS) $(LDLIBS) $(LDFLAGS) -o tf_csv src/obj/hybridModel.o src/obj/standardScaler.o src/obj/ipc.o src/csv.cpp
	@echo Build Success!

dataset: hybridModel_cpp standardScaler_cpp ipc_cpp
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(TF_LIBS) $(LDLIBS) $(LDFLAGS) -o tf_dataset src/obj/hybridModel.o src/obj/standardScaler.o src/obj/ipc.o src/dataset.cpp
	@echo Build Success!

test: ipc_cpp
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(TF_LIBS) $(LDLIBS) $(LDFLAGS) -o test src/obj/ipc.o src/test.cpp

main_cpp:
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(TF_LIBS) $(LDLIBS) $(LDFLAGS) -c src/main.cpp -o src/obj/main.o

hybridModel_cpp:
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(TF_LIBS) $(LDLIBS) $(LDFLAGS) -c src/hybridModel.cpp -o src/obj/hybridModel.o

standardScaler_cpp:
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(TF_LIBS) $(LDLIBS) $(LDFLAGS) -c src/standardScaler.cpp -o src/obj/standardScaler.o

ipc_cpp:
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(TF_LIBS) $(LDLIBS) $(LDFLAGS) -c ../ipc/IPC.cpp -o src/obj/ipc.o


clean:
	-@rm -rf src/obj/*
	-@rm -rf $(EXE_FILE)
