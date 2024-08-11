.PHONY: tests

tests: *.hex
	./run21064-OpenVMS $^
	./run21164-Unix $^
	./run21264-OpenVMS $^

clean:
	rm -rf *.out
	rm -rf core.*
	rm -rf *~
