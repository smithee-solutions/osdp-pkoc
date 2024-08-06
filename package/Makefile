PACKAGE_NAME=osdp-pkoc

package:	all
	cp *.deb ..

all:	makefile-package
	echo `dpkg-architecture | grep DEB_TARGET_ARCH=` printenv DEB_TARGET_ARCH >get-arch
	chmod +x get-arch
	echo architecture is `./get-arch`
	mkdir -p ${PACKAGE_NAME}/DEBIAN
	cp package-control/control-`./get-arch` ${PACKAGE_NAME}/DEBIAN/control
	make -f makefile-package
	mkdir -p ${PACKAGE_NAME}-dist
	dpkg-deb --build ${PACKAGE_NAME} ${PACKAGE_NAME}-dist
	cp ${PACKAGE_NAME}-dist/*.deb .

clean:
	make -f makefile-package clean
	rm -rf ${PACKAGE_NAME} ${PACKAGE_NAME}-build ${PACKAGE_NAME}-dist ${PACKAGE_NAME}*.deb opt  get-arch


