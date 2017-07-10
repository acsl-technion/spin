CC = g++
LDFLAGS = -shared
CXXFLAGS += -fPIC
CXXFLAGS += -Wall
CXXFLAGS += -O3
RM = rm -f
TARGET_LIB = libspin.so

SRCS = spin.cpp
OBJS = $(SRCS:.cpp=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^ -ldl

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.cpp=.d)

