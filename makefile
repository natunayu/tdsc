CC         := gcc
CFLAGS     := -I$(HOME)/local/include -Iinclude -std=gnu99
LDFLAGS    := -L$(HOME)/local/lib -lpbc -lgmp -lssl -lcrypto -lm

SRC_DIR    := src
BUILD_DIR  := build


# -------Settings---------
PARAM_DIR    := param_f.txt
ID           := test1
CURRENT_TIME := 1
EXPIRY_TIME  := 2047
# ------------------------


# コンパイルファイルの追加
APPS       := setup     # → 後から "setup join issue" とかにする

# 共通ユーティリティ
COMMON_SRCS  := \
    $(SRC_DIR)/pbc_utils.c \

COMMON_OBJS  := $(COMMON_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# コンパイルファイルの追加
ARGS_setup := $(PARAM_DIR) $(ID)
# ARGS_join  := $(PARAM_DIR) $(ID)
# ARGS_issue := $(PARAM_DIR) $(ID)

.PHONY: all clean $(addprefix run_,$(APPS))

all: $(APPS:%=$(BUILD_DIR)/%)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%: $(BUILD_DIR)/%.o $(COMMON_OBJS)
	@mkdir -p $(@D)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)

$(addprefix run_,$(APPS)): run_%: $(BUILD_DIR)/%
	@echo ">>> running $* with '$(ARGS_$*)'"
	@./$(BUILD_DIR)/$* $($(patsubst run_%,ARGS_%,$@))
