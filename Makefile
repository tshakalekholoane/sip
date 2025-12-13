.DEFAULT_GOAL = target/sip_test

CFLAGS =                         \
  -O0                            \
  -Wall                          \
  -Weverything                   \
  -Wextra                        \
  -Wno-poison-system-directories \
  -Wno-pre-c23-compat            \
  -fsanitize=address,undefined   \
  -g                             \
  -std=gnu23

MAKEFLAGS += --no-builtin-rules

src/sip_test.c: src/sip.h

target/sip_test: src/sip_test.c src/sip_aarch64_apple.s
	@-mkdir -p $(@D)/
	@$(CC) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	@-rm -fr target/

.PHONY: format
format:
	@clang-format -i src/*.{c,h}
