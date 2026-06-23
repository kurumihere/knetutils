CC := clang
CFLAGS := -Wall -Wextra -pedantic -Werror -O2 -std=c11 -D_GNU_SOURCE -I./include
LDFLAGS := 

SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin

TARGET := $(BIN_DIR)/knetutils

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

.PHONY: all clean links

all: $(TARGET) links

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ -o $@

links: $(TARGET)
	ln -sf knetutils $(BIN_DIR)/arping
	ln -sf knetutils $(BIN_DIR)/ping

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
