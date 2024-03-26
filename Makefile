all:
	echo "Just use cargo for local builds. This script is for cross-compiling"

cc-linux:
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-unknown-linux-gnu-gcc \
	cargo build --target=x86_64-unknown-linux-gnu --release
