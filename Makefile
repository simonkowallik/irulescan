CARGO := cargo
MELANGE_BUILD := sudo melange build --signing-key $(SIGNING_KEY)
MELANGE_SIGN_INDEX := melange sign-index
DOCKER_LOAD := sudo docker load
APKO_BUILD := apko build

LIBTCL_MELANGE_CONFIG := ./files/melange-libtcl-irulescan.yaml
IRULESCAN_MELANGE_CONFIG := ./melange.yaml
SIGNING_KEY := melange.rsa
PACKAGES_DIR := packages
GENERATED_TCL_RS := src/tcl.rs
ARTIFACTS_DIR := artifacts

NAMES := apiserver mcpserver latest
# Ensure yq is installed and available in your environment for this to work

ALL_IRULESCAN_TARGETS := $(foreach name,$(NAMES),irulescan-$(name))

.PHONY: all libtcl-irulescan-pkg irulescan-pkg sign-apkindex lib sign clean apkindex irulescan $(ALL_IRULESCAN_TARGETS)

all: libtcl-irulescan-pkg irulescan-pkg irulescan

sign-apkindex:
	@echo "Signing APK indexes..."
	@for arch_dir in $(PACKAGES_DIR)/*/; do \
		if [ -f "$$arch_dir/APKINDEX.tar.gz" ]; then \
			echo "Signing APK index for $$(basename $$arch_dir)..."; \
			$(MELANGE_SIGN_INDEX) "$$arch_dir/APKINDEX.tar.gz" --signing-key $(SIGNING_KEY); \
		fi; \
	done

libtcl-irulescan-pkg: libtcl-irulescan-pkg-build sign-apkindex

libtcl-irulescan-pkg-build:
	@echo "Building libtcl-irulescan package..."
	$(MELANGE_BUILD) $(LIBTCL_MELANGE_CONFIG)

irulescan-pkg: irulescan-pkg-build sign-apkindex

irulescan-pkg-build:
	@echo "Building irulescan package..."
	$(MELANGE_BUILD) $(IRULESCAN_MELANGE_CONFIG)

irulescan: sign-apkindex $(ALL_IRULESCAN_TARGETS)

define IRULESCAN_TEMPLATE
irulescan-$(1):
	@echo "Building irulescan $(1) container..."
	mkdir -p $(ARTIFACTS_DIR)/$(1)/
	$(APKO_BUILD) \
		--sbom-path $(ARTIFACTS_DIR)/$(1)/ \
		files/apko-$(1).yaml \
		irulescan:$(1) \
		$(ARTIFACTS_DIR)/$(1)/irulescan-$(1).tar
	$(DOCKER_LOAD) < $(ARTIFACTS_DIR)/$(1)/irulescan-$(1).tar
endef

$(foreach name,$(NAMES),$(eval $(call IRULESCAN_TEMPLATE,$(name))))

signing-keys:
	@echo "Generating signing keys..."
	#melange keygen --key-size 4096 $(SIGNING_KEY)
	COSIGN_PASSWORD="" cosign import-key-pair --key=$(SIGNING_KEY) --output-key-prefix=cosign
	rm cosign.pub
	ln -s $(SIGNING_KEY).pub cosign.pub
	mkdir -p signkeys/
	cp $(SIGNING_KEY).pub signkeys/
	cp cosign.pub signkeys/

tag-dockerhub:
	docker manifest create irulescan:latest \
	  --amend irulescan:latest-amd64 \
	  --amend irulescan:latest-arm64
	docker manifest create irulescan:apiserver \
	  --amend irulescan:apiserver-amd64 \
	  --amend irulescan:apiserver-arm64
	docker manifest create irulescan:mcpserver \
	  --amend irulescan:mcpserver-amd64 \
	  --amend irulescan:mcpserver-arm64
	docker manifest push irulescan:latest
	docker manifest push irulescan:apiserver
	docker manifest push irulescan:mcpserver

tag-ghcr:
	docker manifest create ghcr.io/simonkowallik/irulescan:latest \
	  --amend ghcr.io/simonkowallik/irulescan:latest-amd64 \
	  --amend ghcr.io/simonkowallik/irulescan:latest-arm64
	docker manifest create ghcr.io/simonkowallik/irulescan:apiserver \
	  --amend ghcr.io/simonkowallik/irulescan:apiserver-amd64 \
	  --amend ghcr.io/simonkowallik/irulescan:apiserver-arm64
	docker manifest create ghcr.io/simonkowallik/irulescan:mcpserver \
	  --amend ghcr.io/simonkowallik/irulescan:mcpserver-amd64 \
	  --amend ghcr.io/simonkowallik/irulescan:mcpserver-arm64
	docker manifest push ghcr.io/simonkowallik/irulescan:latest
	docker manifest push ghcr.io/simonkowallik/irulescan:apiserver
	docker manifest push ghcr.io/simonkowallik/irulescan:mcpserver

sign-dockerhub:
	cosign sign --key cosign.key --recursive \
	irulescan:latest
	cosign sign --key cosign.key --recursive \
	irulescan:apiserver
	cosign sign --key cosign.key --recursive \
	irulescan:mcpserver

sign-ghcr:
	cosign sign --key cosign.key --recursive \
  	ghcr.io/simonkowallik/irulescan:latest
	cosign sign --key cosign.key --recursive \
  	ghcr.io/simonkowallik/irulescan:apiserver
	cosign sign --key cosign.key --recursive \
  	ghcr.io/simonkowallik/irulescan:mcpserver

clean:
	@echo "Cleaning up project..."
	$(CARGO) clean
	rm -rf $(PACKAGES_DIR)
	rm -f $(GENERATED_TCL_RS)
	rm -rf $(ARTIFACTS_DIR)
	@echo "Cleanup complete."
