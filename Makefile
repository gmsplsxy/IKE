SRCDIR = src
HDRDIR = include
OBJDIR = .build

PROGRAM = $(OBJDIR)/IKE

SRCS = $(wildcard $(SRCDIR)/*.c)
HDRS = $(wildcard $(SRCDIR)/*.h)
OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))

CFLAGS = -Wall -Wextra -lconfig

ifeq ($(shell id -u), 0)
all: clean run
else
all: clean compile
endif

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	gcc -c $< $(CFLAGS) -I$(HDRDIR) -o $@

$(PROGRAM): $(OBJS)
	gcc $^ $(CFLAGS) -o $@

run: $(PROGRAM)
	$(PROGRAM)

compile:
	compiledb -n make $(PROGRAM)

clean:
	rm -rf $(OBJDIR)/*
