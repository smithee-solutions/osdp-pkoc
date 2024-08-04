all:
	(cd src; make)

clean:
	(cd src; make clean)
	(cd package; make clean)
	rm -rf opt

package:	all
	mkdir -p opt/osdp-conformance/etc/pkoc
	cp actions/* opt/osdp-conformance/etc/pkoc
	(cd package; make)

