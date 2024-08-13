.PHONY: tests

tests: *.hex
	./runtest 21064 VMS $^
	./runtest 21164 UNIX $^
	./runtest 21264 NT $^

clean:
	rm -rf *.out
	rm -rf core.*
	rm -rf *~
