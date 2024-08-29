CC ?= gcc
ifeq ($(OS), Windows_NT)
EXE_SUFFIX := .exe
endif

BUILD_DIR ?= ./build

SRCS := lib/epicac.c
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)

INC_DIRS := ./lib
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CC := gcc
CFLAGS ?= $(INC_FLAGS) -O2 -Wall -Wextra -Werror -std=c11 -pedantic

.PHONY: meow epicat

EPICAT_EXE := $(BUILD_DIR)/epicat$(EXE_SUFFIX)
epicat: $(EPICAT_EXE)
$(EPICAT_EXE): $(OBJS) $(BUILD_DIR)/cli/main.c.o
	$(CC) $^ -o $@ $(LDFLAGS)

MEOW_EXE := $(BUILD_DIR)/meow$(EXE_SUFFIX)
meow: $(MEOW_EXE)
$(MEOW_EXE): $(OBJS) $(BUILD_DIR)/meow.c.o
	$(CC) $^ -o $@ $(LDFLAGS)

# C source
$(BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR)

# TODO:
# all:
# default:
# test:
# format:
# lint:
# static:
# shared:
# node:
# python:



MKDIR_P ?= mkdir -p
