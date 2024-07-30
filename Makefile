all:
	(cd src; make)

clean:
	(cd src; make clean)
	(cd package; make clean)

package:	all
	(cd package; make)

