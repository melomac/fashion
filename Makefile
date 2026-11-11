.PHONY: all
all: release

# ----------------------------------------------------------------------------
# Swift
# ----------------------------------------------------------------------------

.PHONY: debug
debug:
	swift build

.PHONY: test
test:
	swift test --enable-code-coverage
	# Again with the other --exact ending (see Package.swift), in its own build directory.
	SECURITY_STRICT_VALIDATION=NO swift test --scratch-path .build/segments

.PHONY: format
format:
	swiftformat . --verbose

.PHONY: clean
clean:
	swift package clean

# ----------------------------------------------------------------------------
# Xcode
# ----------------------------------------------------------------------------

PRODUCT_NAME = fashion
CONFIG_PATH ?= $(PRODUCT_NAME).xcconfig
XCODE_FLAGS = -scheme $(PRODUCT_NAME) -xcconfig $(CONFIG_PATH)
BUILD_FLAGS = -target $(PRODUCT_NAME) -destination generic/platform=macOS
TEST_FLAGS = -target $(PRODUCT_NAME)Tests -destination platform=macOS

INSTALL_PATH ?= /usr/local/bin/
ARCHIVE_PATH = /tmp/fashion.zip

.PHONY: release
release: xcode
	xcodebuild build $(XCODE_FLAGS) $(BUILD_FLAGS) -configuration Release

.PHONY: xcode-debug
xcode-debug: xcode
	xcodebuild build $(XCODE_FLAGS) $(BUILD_FLAGS) -configuration Debug

.PHONY: xcode-test
xcode-test: xcode
	xcodebuild test $(XCODE_FLAGS) $(TEST_FLAGS)

.PHONY: xcode-clean
xcode-clean: xcode
	xcodebuild clean -scheme $(PRODUCT_NAME) -destination platform=macOS -alltargets
	rm -rf /tmp/$(PRODUCT_NAME).dst

.PHONY: install
install: release
	cp /tmp/$(PRODUCT_NAME).dst/usr/local/bin/$(PRODUCT_NAME) $(INSTALL_PATH)

.PHONY: zip
zip: release
	rm -f $(ARCHIVE_PATH)
	zip -j $(ARCHIVE_PATH) /tmp/$(PRODUCT_NAME).dst/usr/local/bin/$(PRODUCT_NAME) LICENSE NOTICE

# ----------------------------------------------------------------------------
# Setup dependencies
# ----------------------------------------------------------------------------

.PHONY: xcode
xcode:
	xcode-select --print-path
	xcodebuild -runFirstLaunch

.PHONY: brew
brew: xcode
	[ -f /etc/paths.d/*brew ] \
	|| /bin/bash -c "$$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
	&& eval "$$(/usr/libexec/path_helper)" \
	&& ( HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_OFFLINE=1 brew bundle check --no-upgrade --file Brewfile || brew bundle --file Brewfile )

# ----------------------------------------------------------------------------
# Fuzzing (see Fuzz/README.md)
# ----------------------------------------------------------------------------

FUZZ_SECONDS ?= 900
FUZZ_HARNESSES ?=
FUZZ_FROM ?=

.PHONY: fuzz
fuzz:
	Fuzz/fuzz.sh build

.PHONY: fuzz-seed
fuzz-seed:
	Fuzz/fuzz.sh seed

.PHONY: fuzz-run
fuzz-run: fuzz
	Fuzz/fuzz.sh run $(FUZZ_SECONDS) $(FUZZ_HARNESSES)

.PHONY: fuzz-watch
fuzz-watch:
	Fuzz/fuzz.sh watch $(FUZZ_HARNESSES)

.PHONY: fuzz-merge
fuzz-merge:
	Fuzz/fuzz.sh merge $(FUZZ_FROM) $(FUZZ_HARNESSES)

.PHONY: fuzz-coverage
fuzz-coverage:
	Fuzz/fuzz.sh coverage $(FUZZ_HARNESSES)

.PHONY: fuzz-clean
fuzz-clean:
	Fuzz/fuzz.sh clean

# ----------------------------------------------------------------------------
# Housekeeping
# ----------------------------------------------------------------------------

.PHONY: distclean
distclean: clean xcode-clean
	git clean -dx --force --exclude local.xcconfig --exclude submodules
