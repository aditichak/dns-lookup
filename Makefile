all: 
	javac DNSlookup.java
	jar cvfe DNSlookup.jar DNSlookup *.class

run: DNSlookup.jar
	java -jar DNSlookup.jar   199.7.83.42 groups.yahoo.com   -t
clean:
	rm -f *.class
	rm -f DNSlookup.jar
