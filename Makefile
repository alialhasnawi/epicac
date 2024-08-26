CC ?= gcc
TARGET_EXEC ?= main

BUILD_DIR ?= ./build

SRCS := lib/epicac.c meow.c
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)

INC_DIRS := ./lib
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CFLAGS ?= $(INC_FLAGS) -O2 -Wall -Wextra -Werror -std=c11 -pedantic -Wno-unused-variable -Wno-unused-function

$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	gcc $(OBJS) -o $@ $(LDFLAGS)

# c source
$(BUILD_DIR)/%.c.o: %.c
	$(MKDIR_P) $(dir $@)
	gcc $(CFLAGS) -c $< -o $@

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
