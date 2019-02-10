SRCS = $(wildcard *.java)
CLS  = $(SRCS:.java=.class)

default:
	javac -classpath . $(SRCS)

clean:
	$(RM) *.class result history *.pb *.pr