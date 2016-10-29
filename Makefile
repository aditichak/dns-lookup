all: 
	javac DNSlookup.java
	jar cvfe DNSlookup.jar DNSlookup *.class

run: DNSlookup.jar
	java -jar DNSlookup.jar   142.103.6.6 www.cs.ubc.ca   -t
clean:
	rm -f *.class
	rm -f DNSlookup.jar
