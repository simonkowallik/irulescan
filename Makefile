libtcl-irulescan-pkg:
	sudo melange build ./files/melange-libtcl-irulescan.yaml

sign-apkindex:
	melange sign-index packages/x86_64/APKINDEX.tar.gz --signing-key melange.rsa
	melange sign-index packages/aarch64/APKINDEX.tar.gz --signing-key melange.rsa

irulescan-pkg:
	sudo melange build ./melange.yaml

lib: libtcl-irulescan-pkg

sign: sign-apkindex

all:
	lib
	sign-apkindex
	irulescan-pkg

clean:
	rm -rf packages
	rm -rf build
	cargo clean
	rm -f src/tcl.rs
