/*

     Copyright (C) 2017 Proxmox Server Solutions GmbH

     Copyright: vncterm is under GNU GPL, the GNU General Public License.

     This program is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation; version 2 dated June, 1991.

     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with this program; if not, write to the Free Software
     Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
     02111-1307, USA.

     Author: Dominik Csapak <d.csapak@proxmox.com>

     This tool converts the unifont.hex file format into
     a binary format used in vncterm to render glyphs.
*/


#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <getopt.h>

#define NUMCODEPOINTS 0xFFFF
#define GLYPHLINES 16
#define INDEXLENGTH 4

/* parses strings like 00F0 to the integer */
long
parsehex(char *val, size_t length)
{
    unsigned int value = 0;

    for (size_t i = 0; i < length; i++) {
	value *= 16;
	if (val[i] >= '0' && val[i] <= '9') {
	    value += (val[i] - '0');
	} else if (val[i] >= 'A' && val[i] <= 'F') {
	    value += (val[i] - 'A' + 10);
	} else if (val[i] >= 'a' && val[i] <= 'f') {
	    value += (val[i] - 'a' + 10);
	} else {
	    return -1;
	}
    }

    return value;
}

void usage(char **argv) {
    printf("Usage: %s [OPTION]...\n", argv[0]);
    printf("Converts font data from hex format into binary format used by vncterm.\n");

    printf("\n");
    printf("  -o, --output    file for output, if omitted, write to STDOUT\n");
    printf("  -i, --input     file for input, if omitted read from STDIN\n");
    printf("  -h, --help      display this help\n");

    printf("\nThe input has to be formatted in the hex format of unifont.\n");
}

int
main (int argc, char** argv)
{
    FILE *fd;
    FILE *outfd;
    char *line = NULL;
    char *tmp = NULL;
    char *fontfile = NULL;
    char *outfile = NULL;
    size_t linesize = 0;
    uint8_t emptyglyph[GLYPHLINES*2] = { 0 };
    uint8_t glyph[GLYPHLINES*2] = { 0 };
    int nextcodepoint = 0;
    int codepoint = 0;
    int c;

    static struct option long_options[] = {
	{"help", no_argument, 0, 'h'},
	{"output", required_argument, 0, 'o'},
	{"input", required_argument, 0, 'i'},
	{ 0 , 0, 0, 0}
    };
    int option_index = 0;

    while((c = getopt_long(argc, argv, "hi:o:", long_options, &option_index)) != -1) {
	switch (c) {
	    case 'h':
		usage(argv);
		exit(0);
		break;
	    case 'o':
		outfile = optarg;
		break;
	    case 'i':
		fontfile = optarg;
		break;
	    default:
		usage(argv);
		exit(1);
	}
    }

    if (fontfile != NULL){
	fd = fopen(fontfile, "r");
	if (fd == NULL) {
	    fprintf(stderr, "Error opening '%s'\n", fontfile);
	    perror(NULL);
	    exit(2);
	}
    } else {
	fd = stdin;
    }

    if (outfile != NULL) {
	outfd = fopen(outfile, "w");
	if (outfd == NULL) {
	    fprintf(stderr, "Error opening '%s'\n", outfile);
	    perror(NULL);
	    exit(2);
	}
    } else {
	outfd = stdout;
    }


    while (getline(&line, &linesize, fd) != -1) {
	codepoint = parsehex(line, INDEXLENGTH);
	if (codepoint == -1) {
	    fprintf(stderr, "Cannot parse codepoint index: '%s'\n", line);
	    free(line);
	    exit(4);
	}

	/* fill in missing codepoints with empty glyphs */
	while (nextcodepoint++ < codepoint) {
	    fwrite(emptyglyph, sizeof(emptyglyph), 1, outfd);
	}

	tmp = line + INDEXLENGTH + 1;
	size_t i = 0;

	/* parse until end of line */
	while (*(tmp+i*2) != '\n' && i < sizeof(glyph)) {
	    int value = parsehex(tmp+i*2, 2);

	    if (value == -1) {
		fprintf(stderr, "Cannot parse glyph from line: '%s' at position %ld ('%s')\n", line, i*2, tmp+i*2);
		free(line);
		exit(4);
	    }

	    glyph[i++] = (uint8_t)value;
	}

	/* if we have a 1width glyph, fill the rest with zeroes */
	while (i < sizeof(glyph)) {
	    glyph[i++] = 0;
	}

	fwrite(glyph, sizeof(glyph), 1, outfd);
    }

    if(errno) {
	perror("Cannot not read line from file");
    }

    while (nextcodepoint++ <= NUMCODEPOINTS) {
	fwrite(emptyglyph, sizeof(emptyglyph), 1, outfd);
    }

    free(line);
    exit(0);
}
