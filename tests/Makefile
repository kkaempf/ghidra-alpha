.PHONY: tests

tests: *.hex
	./run21064 $^
	./run21164 $^
	./run21264 $^

clean:
	rm -rf *.out
	rm -rf core.*
	rm -rf *~
