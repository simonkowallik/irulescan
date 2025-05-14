CARGO := cargo
MELANGE_BUILD := sudo melange build
MELANGE_SIGN_INDEX := melange sign-index
DOCKER_LOAD := sudo docker load
APKO_BUILD := apko build

LIBTCL_MELANGE_CONFIG := ./files/melange-libtcl-irulescan.yaml
IRULESCAN_MELANGE_CONFIG := ./melange.yaml
SIGNING_KEY := melange.rsa
PACKAGES_DIR := packages
X86_64_APKINDEX := $(PACKAGES_DIR)/x86_64/APKINDEX.tar.gz
AARCH64_APKINDEX := $(PACKAGES_DIR)/aarch64/APKINDEX.tar.gz
GENERATED_TCL_RS := src/tcl.rs

.PHONY: all libtcl-irulescan-pkg irulescan-pkg sign-apkindex lib sign clean packages_build apkindex irulescan

all: libtcl-irulescan-pkg irulescan-pkg irulescan

sign-apkindex: packages_build
	@echo "Signing APK indexes..."
	$(MELANGE_SIGN_INDEX) $(X86_64_APKINDEX) --signing-key $(SIGNING_KEY)
	$(MELANGE_SIGN_INDEX) $(AARCH64_APKINDEX) --signing-key $(SIGNING_KEY)

libtcl-irulescan-pkg: libtcl-irulescan-pkg-build sign-apkindex

libtcl-irulescan-pkg-build:
	@echo "Building libtcl-irulescan package..."
	$(MELANGE_BUILD) $(LIBTCL_MELANGE_CONFIG)

irulescan-pkg: irulescan-pkg-build sign-apkindex

irulescan-pkg-build:
	@echo "Building irulescan package..."
	$(MELANGE_BUILD) $(IRULESCAN_MELANGE_CONFIG)

irulescan: irulescan-apiserver irulescan-mcpserver irulescan-default

irulescan-apiserver:
	@echo "Building irulescan API server container..."
	$(APKO_BUILD) files/apko-apiserver.yaml irulescan:apiserver irulescan-apiserver-container.tar
	$(DOCKER_LOAD) < irulescan-apiserver-container.tar

irulescan-mcpserver:
	@echo "Building irulescan MCP server container..."
	$(APKO_BUILD) files/apko-mcpserver.yaml irulescan:mcpserver irulescan-mcpserver-container.tar
	$(DOCKER_LOAD) < irulescan-mcpserver-container.tar

irulescan-default:
	@echo "Building irulescan default container..."
	$(APKO_BUILD) files/apko-default.yaml irulescan:latest irulescan-latest-container.tar
	$(DOCKER_LOAD) < irulescan-latest-container.tar

clean:
	@echo "Cleaning up project..."
	rm -rf $(PACKAGES_DIR)
	$(CARGO) clean
	rm -f $(GENERATED_TCL_RS)
	rm -rf build
	rm -f irulescan-apiserver-container.tar
	rm -f irulescan-mcpserver-container.tar
	rm -f irulescan-latest-container.tar
	rm -f sbom-*.spdx.json
	@echo "Cleanup complete."
