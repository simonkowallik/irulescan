LIBTCL_MELANGE_CONFIG := files/melange-libtcl-irulescan.yaml
IRULESCAN_MELANGE_CONFIG := melange.yaml
SIGNING_KEY := melange.rsa
PACKAGES_DIR := packages
GENERATED_TCL_RS := src/tcl.rs
ARTIFACTS_DIR := artifacts
CARGO := cargo
MELANGE_BUILD := sudo melange build --signing-key $(SIGNING_KEY)
MELANGE_SIGN_INDEX := melange sign-index
DOCKER_LOAD := sudo docker load
APKO_BUILD := apko build

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
	docker manifest create simonkowallik/irulescan:latest \
	  --amend simonkowallik/irulescan:latest-amd64 \
	  --amend simonkowallik/irulescan:latest-arm64
	docker manifest create simonkowallik/irulescan:apiserver \
	  --amend simonkowallik/irulescan:apiserver-amd64 \
	  --amend simonkowallik/irulescan:apiserver-arm64
	docker manifest create simonkowallik/irulescan:mcpserver \
	  --amend simonkowallik/irulescan:mcpserver-amd64 \
	  --amend simonkowallik/irulescan:mcpserver-arm64
	docker manifest push simonkowallik/irulescan:latest
	docker manifest push simonkowallik/irulescan:apiserver
	docker manifest push simonkowallik/irulescan:mcpserver

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

cosign-images:
	cosign sign --yes=true --key cosign.key --recursive ghcr.io/simonkowallik/irulescan@sha256:62de09da0756420037de64a1398530b1ed205d4b260deffe2e758fb3d93c1c95
	cosign sign --yes=true --key cosign.key --recursive ghcr.io/simonkowallik/irulescan@sha256:7e40e5755589a83df68cce82c04b458284ab0835788a353da05c2cea06fc6825
	cosign sign --yes=true --key cosign.key --recursive ghcr.io/simonkowallik/irulescan@sha256:9742d155ecfc817a728f48db696c2fba20916d2f9ce838dad0e83d66676d1131
	cosign sign --yes=true --key cosign.key --recursive ghcr.io/simonkowallik/irulescan@sha256:ddf62a70606f3f52133ddb2c5fc4fe43de3ae0d3094def48ca237390a94a659d
	cosign sign --yes=true --key cosign.key --recursive ghcr.io/simonkowallik/irulescan@sha256:ee57ed61349fc01aa3b5b3089972b0a7cea205dfb5ad9c541865ee23125534b8
	cosign sign --yes=true --key cosign.key --recursive ghcr.io/simonkowallik/irulescan@sha256:f6e004193c9d21a6134ff5b173a34d68b501d8848d30c7fbc278e5f862077281
	cosign sign --yes=true --key cosign.key --recursive simonkowallik/irulescan@sha256:62de09da0756420037de64a1398530b1ed205d4b260deffe2e758fb3d93c1c95
	cosign sign --yes=true --key cosign.key --recursive simonkowallik/irulescan@sha256:7e40e5755589a83df68cce82c04b458284ab0835788a353da05c2cea06fc6825
	cosign sign --yes=true --key cosign.key --recursive simonkowallik/irulescan@sha256:9742d155ecfc817a728f48db696c2fba20916d2f9ce838dad0e83d66676d1131
	cosign sign --yes=true --key cosign.key --recursive simonkowallik/irulescan@sha256:ddf62a70606f3f52133ddb2c5fc4fe43de3ae0d3094def48ca237390a94a659d
	cosign sign --yes=true --key cosign.key --recursive simonkowallik/irulescan@sha256:ee57ed61349fc01aa3b5b3089972b0a7cea205dfb5ad9c541865ee23125534b8
	cosign sign --yes=true --key cosign.key --recursive simonkowallik/irulescan@sha256:f6e004193c9d21a6134ff5b173a34d68b501d8848d30c7fbc278e5f862077281

clean:
	@echo "Cleaning up project..."
	$(CARGO) clean
	rm -rf $(PACKAGES_DIR)
	rm -f $(GENERATED_TCL_RS)
	rm -rf $(ARTIFACTS_DIR)
	@echo "Cleanup complete."
