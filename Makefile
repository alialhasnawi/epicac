INC_DIRS := ./lib

ifeq ($(OS), Windows_NT)
EXE_SUFFIX := .exe
WINDOWS := 1

ifdef MSCV
  CC := cl.exe
  INC_FLAGS := $(addprefix /I,$(INC_DIRS))
  CFLAGS ?= $(INC_FLAGS)
  ifneq ($(DEBUG),)
  CFLAGS := $(CFLAGS) /Zi /fsanitize=address
  endif
else
  CC := gcc
  INC_FLAGS := $(addprefix -I,$(INC_DIRS))
  CFLAGS ?= $(INC_FLAGS) -O2 -Wall -Wextra -Werror -std=c11 -pedantic
  ifneq ($(DEBUG),)
  CFLAGS := $(CFLAGS) -g -Og -fsanitize=address
  LDFLAGS := $(LDFLAGS) -fsanitize=address -static-libasan
  endif
endif

else
CC := gcc
INC_FLAGS := $(addprefix -I,$(INC_DIRS))
CFLAGS ?= $(INC_FLAGS) -O2 -Wall -Wextra -Werror -std=c11 -pedantic
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
ifdef MSCV
$(EPICAT_EXE): ./lib/epicac.c ./cli/main.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ /link /out:$@
else
$(EPICAT_EXE): $(OBJS) $(BUILD_DIR)/cli/main.c.o
	$(CC) $^ -o $@ $(LDFLAGS)
endif

TEST_EXE := $(BUILD_DIR)/test_main$(EXE_SUFFIX)
test: $(TEST_EXE)
	$(TEST_EXE)

ifdef MSCV
$(TEST_EXE): ./lib/epicac.c ./test/test.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ /link /out:$@
else
$(TEST_EXE): $(OBJS) $(BUILD_DIR)/test/test.c.o
	$(CC) $^ -o $@ $(LDFLAGS)
endif

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
