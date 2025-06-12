obj-m := neo.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

CC := $(CROSS_COMPILE)gcc
CXX := $(CROSS_COMPILE)g++
AR := $(CROSS_COMPILE)ar

CF := -O2 -fPIC -Wall -Wextra
CXXF := -O2 -fPIC -Wall -Wextra -std=c++11

NDK ?= $(NDK_ROOT)
ifdef NDK
	API ?= 21
	ARCH ?= arm64-v8a
	
	ifeq ($(ARCH),arm64-v8a)
		TCH := aarch64-linux-android
		CLANG := aarch64-linux-android$(API)
	else ifeq ($(ARCH),armeabi-v7a)
		TCH := armv7a-linux-androideabi
		CLANG := armv7a-linux-androideabi$(API)
	else ifeq ($(ARCH),x86_64)
		TCH := x86_64-linux-android
		CLANG := x86_64-linux-android$(API)
	else ifeq ($(ARCH),x86)
		TCH := i686-linux-android
		CLANG := i686-linux-android$(API)
	endif
	
	TC_DIR := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64
	SYS := $(TC_DIR)/sysroot
	
	CC := $(TC_DIR)/bin/$(CLANG)-clang
	CXX := $(TC_DIR)/bin/$(CLANG)-clang++
	AR := $(TC_DIR)/bin/llvm-ar
	
	CF += --sysroot=$(SYS)
	CXXF += --sysroot=$(SYS)
endif

.PHONY: all drv lib clean install uninstall android

all: drv lib

drv:
	if [ -d "$(KDIR)" ]; then \
		$(MAKE) -C $(KDIR) M=$(PWD) modules; \
	else \
		echo "Kernel headers not found in $(KDIR). Skipping driver build."; \
	fi

lib: libneo.a libneo.so

libneo.a: neo_impl.o
	$(AR) rcs $@ $^

libneo.so: neo_impl.o
	$(CC) -shared -o $@ $^ $(CF)

neo_impl.o: neo_impl.c neo.h
	$(CC) $(CF) -c -o $@ $<

android: libneo_a.a libneo_s.so

libneo_a.a: neo_impl_a.o
	$(AR) rcs $@ $^

libneo_s.so: neo_impl_a.o
	$(CC) -shared -o $@ $^ $(CF)

neo_impl_a.o: neo_impl.c neo.h
	$(CC) $(CF) -DANDROID_BUILD -c -o $@ $<

install: drv
	sudo cp neo.ko /lib/modules/$(shell uname -r)/kernel/drivers/
	sudo depmod -a
	sudo modprobe neo
	sudo chmod 666 /dev/neo

uninstall:
	sudo rmmod neo || true
	sudo rm -f /lib/modules/$(shell uname -r)/kernel/drivers/neo.ko
	sudo depmod -a

clean:
	if [ -d "$(KDIR)" ]; then \
		$(MAKE) -C $(KDIR) M=$(PWD) clean; \
	fi
	rm -f *.o *.a *.so
	rm -f neo_impl_a.o libneo_a.*

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

help:
	@echo "Targets:"
	@echo "  all"
	@echo "  drv"
	@echo "  lib"
	@echo "  android"
	@echo "  install"
	@echo "  uninstall"
	@echo "  clean"
	@echo ""
	@echo "  NDK"
	@echo "  API"
	@echo "  ARCH"
