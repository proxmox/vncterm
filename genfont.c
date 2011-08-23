/*
 
     Copyright (C) 2007 Proxmox Server Solutions GmbH
 
     Copyright: vzdump is under GNU GPL, the GNU General Public License.
 
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
 
     Author: Dietmar Maurer <dietmar@proxmox.com>

*/

#include <stdio.h>
#include <stdlib.h>
#include <zlib.h> /* read compressed console fonts */
#include <glob.h>
#include <string.h>

/* map unicode to font */
static unsigned short vt_fontmap[65536];

/* font glyph storage */
static unsigned char *vt_font_data = NULL;
static int vt_font_size = 0;
static int vt_font_maxsize = 0;

/* PSF stuff */


#define PSF_MAGIC1	0x36
#define PSF_MAGIC2	0x04

#define PSF_MODE256NOSFM	0
#define PSF_MODE512NOSFM	1
#define PSF_MODE256SFM		2
#define PSF_MODE512SFM		3

#define PSF_SEPARATOR	0xFFFF

struct psf_header
{
  unsigned char magic1, magic2;	/* Magic number */
  unsigned char mode;		/* PSF font mode */
  unsigned char charheight;	/* Character size */
};

#define PSF_MAGIC_OK(x)	((x).magic1 == PSF_MAGIC1 && (x).magic2 == PSF_MAGIC2)
#define PSF_MODE_VALID(x) ((x) <= PSF_MODE512SFM)
#define PSF_MODE_HAS512(x) (((x) == 1) || ((x) == 3))
#define PSF_MODE_HASSFM(x) (((x) == 2) || ((x) == 3))

typedef unsigned short unicode;

static int
font_add_glyph (const char *data)
{

  if (vt_font_size >= vt_font_maxsize) {
    vt_font_maxsize += 256;
    vt_font_data = realloc (vt_font_data, vt_font_maxsize*16);
  }

  memcpy (vt_font_data + vt_font_size*16, data, 16);

  vt_font_size += 1;
  
  return vt_font_size - 1;
}

static int
load_psf_font (const char *filename, int is_default)
{
  struct psf_header psfhdr;
 
  gzFile *f = gzopen (filename, "rb");
  if (f == NULL) {
	  fprintf (stderr, "unable to read file %s\n", filename);
	  exit(-1);
  }

  // read psf header
  if (gzread(f, &psfhdr, sizeof(struct psf_header)) !=  sizeof(struct psf_header)) {
    fprintf (stderr, "unable to read psf font header (%s)\n", filename);
    gzclose (f);
    return -1;
  }

  if (!PSF_MAGIC_OK(psfhdr) || !PSF_MODE_VALID(psfhdr.mode) || 
      !PSF_MODE_HASSFM(psfhdr.mode) || (psfhdr.charheight != 16)) {
    fprintf (stderr, "no valid 8*16 psf font (%s)\n", filename);
    gzclose (f);
    return -1;
  }

  int charcount = ((PSF_MODE_HAS512(psfhdr.mode)) ? 512 : 256);

  int size = 16*charcount;

  char *chardata = (char *)malloc (size);

  if (size != gzread(f, chardata, size)) {
    fprintf (stderr, "unable to read font character data (%s)\n", filename);
    gzclose (f);
    return -1;
  }

  unicode unichar;
  int glyph;

  for (glyph = 0 ;glyph < charcount ;glyph++) {
    int fi = 0;
    while (gzread (f, &unichar, sizeof(unicode)) ==  sizeof(unicode) && 
	   (unichar != PSF_SEPARATOR)) {
      if (!vt_fontmap[unichar]) {
	if (!fi) {
	  fi = font_add_glyph (chardata + glyph*16);
	}
	vt_fontmap[unichar] = fi;
      }
    }

    if (is_default && fi && glyph < 256) {
      vt_fontmap[0xf000 + glyph] = fi;      
    }
  }

  free (chardata);
  gzclose (f);

  return 0;
}

void
print_glyphs ()
{
  int i, j;

  printf ("static int vt_font_size = %d;\n\n", vt_font_size);

  printf ("static unsigned char vt_font_data[] = {\n");
  for (i = 0; i < vt_font_size; i++) {
    printf ("\t/* %d 0x%02x */\n", i, i);
    for (j = 0; j < 16; j++) {
      unsigned char d = vt_font_data[i*16+j];
      printf ("\t0x%02X, /* ", d);
      int k;
      for (k = 128; k > 0; k = k>>1) {
	printf ("%c", (d & k) ? '1': '0'); 
      }  
      printf (" */\n");
    }
    printf ("\n");
  }
  printf ("};\n\n");

  printf ("static unsigned short vt_fontmap[65536] = {\n");
  for (i = 0; i < 0x0ffff; i++) {
    printf ("\t/* 0x%04X => */ %d,\n", i, vt_fontmap[i]);
  }
  printf ("};\n\n");

}

int 
main (int argc, char** argv)
{
  char empty[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
  glob_t globbuf;

  font_add_glyph (empty);

  /* font load order is only important if glyphs are redefined */
  load_psf_font ("/usr/share/consolefonts/default8x16.psf.gz", 1);  /* vga default */
  load_psf_font ("/usr/share/consolefonts/lat1u-16.psf.gz", 0);     /* Latin-1 */
  load_psf_font ("/usr/share/consolefonts/lat2u-16.psf.gz", 0);     /* Latin-2 */
  load_psf_font ("/usr/share/consolefonts/lat4u-16.psf.gz", 0);     /* Baltic */

  load_psf_font ("/usr/share/consolefonts/iso07.f16.psf.gz", 0);    /* Greek */
  load_psf_font ("/usr/share/consolefonts/Goha-16.psf.gz", 0);      /* Ethiopic */

  /* fixme: Arabic, Japanese letters ? */

  if (0) {
    glob("/usr/share/consolefonts/*", GLOB_ERR, NULL, &globbuf);

    int i;
    for (i = 0; i < globbuf.gl_pathc; i++) {
      int pc = vt_font_size;
      load_psf_font (globbuf.gl_pathv[i], 0);
      if (vt_font_size > pc) {
	printf ("TEST: %s %d\n", globbuf.gl_pathv[i], vt_font_size - pc);
      }
    }
  } else {

    print_glyphs ();

  }

  exit (0);
}
