CFLAGS=-Wall -Wmissing-prototypes -Wstrict-prototypes -O2 -fomit-frame-pointer

LXDIALOG := lxdialog/checklist.o lxdialog/inputbox.o lxdialog/menubox.o lxdialog/textbox.o lxdialog/util.o lxdialog/yesno.o

conf: conf.o zconf.tab.o

RELEASE=$(shell lsb_release -si)
ifeq ($(RELEASE), Ubuntu)
	AS_NEEDED=--no-as-needed
else
	AS_NEEDED=--add-needed
endif
mconf: LDFLAGS = -Wl,$(AS_NEEDED) $(shell ./lxdialog/check-lxdialog.sh -ldflags $(CC))

mconf: CFLAGS += -DCURSES_LOC="<ncurses.h>" -DLOCALE
mconf: mconf.o zconf.tab.o $(LXDIALOG)

.PHONY: clean
clean:
	@rm -f mconf conf *.o lxdialog/*.o
