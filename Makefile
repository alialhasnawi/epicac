INC_DIRS := ./lib

ifeq ($(OS), Windows_NT)
EXE_SUFFIX := .exe
WINDOWS := 1

CC := gcc
INC_FLAGS := $(addprefix -I,$(INC_DIRS))
CFLAGS ?= $(INC_FLAGS) -O3 -Wall -Wextra -Werror -std=c11 -pedantic -g
ifneq ($(DEBUG),)
CFLAGS := $(CFLAGS) -g -Og -fsanitize=address
LDFLAGS := $(LDFLAGS) -fsanitize=address -static-libasan
endif

else
CC := gcc
INC_FLAGS := $(addprefix -I,$(INC_DIRS))
CFLAGS ?= $(INC_FLAGS) -O3 -Wall -Wextra -Werror -std=c11 -pedantic -g
ifneq ($(DEBUG),)
CFLAGS := $(CFLAGS) -g -Og -fsanitize=address
LDFLAGS := $(LDFLAGS) -fsanitize=address -static-libasan
endif
endif

BUILD_DIR ?= ./build
SRCS := lib/epicac.c
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)


.PHONY: meow epicat test

EPICAT_EXE := $(BUILD_DIR)/epicat$(EXE_SUFFIX)
epicat: $(EPICAT_EXE)
$(EPICAT_EXE): $(OBJS) $(BUILD_DIR)/cli/main.c.o
	$(CC) $^ -o $@ $(LDFLAGS)

TEST_EXE := $(BUILD_DIR)/test_main$(EXE_SUFFIX)
test: $(TEST_EXE)
	$(TEST_EXE)

$(TEST_EXE): $(OBJS) $(BUILD_DIR)/test/test.c.o
	$(CC) $^ -o $@ $(LDFLAGS)

BENCH_EXE := $(BUILD_DIR)/bench_main$(EXE_SUFFIX)
bench: $(BENCH_EXE)
	$(BENCH_EXE)

$(BENCH_EXE): $(OBJS) $(BUILD_DIR)/test/bench.c.o
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
