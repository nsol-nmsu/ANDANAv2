#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int convert(unsigned char *inbuf, unsigned char *outbuf, int outlimit) {
  int inlen=strlen(inbuf);
  int i = 0;
  int o = 0;
  unsigned int v = 0;
  while (i < inlen && o < outlimit) {
    if (inbuf[i] == '%') {
      v = v << 4;
      i++;
      if (isdigit(inbuf[i])) v |= inbuf[i] - '0';
      if (isalpha(inbuf[i])) v |= 10 + (tolower(inbuf[i]) - 'a');
      v = v << 4;
      i++;
      if (isdigit(inbuf[i])) v |= (inbuf[i] - '0');
      if (isalpha(inbuf[i])) v |= (10 + (tolower(inbuf[i]) - 'a'));
      i++;
    } else {
      v = v << 8;
      v |= inbuf[i];
      i++;
    }
    outbuf[o++] = (unsigned char) v;
  }
  return (o);
}

int main (int argc, char *argv[]) {
  unsigned char inbuf[4096];
  unsigned char *outbuf;
  unsigned char *inbufp;
  int inlen, outlen, i;
  int value;
  if (argc > 2) {
    fprintf(stderr, "Usage: depercent %%00%%01p or depercent <in\n");
    exit(1);
  }
  if (argc == 2) {
    inlen = strlen(argv[1]);
    outbuf = calloc(1, inlen); /* output must be <= input size */
    outlen = convert(argv[1], outbuf, inlen);
      write(1, outbuf, outlen);
  } else {
    while ((inbufp = fgets(inbuf, sizeof(inbuf), stdin)) != NULL) {
      inlen = strlen(inbuf);
      if (inbufp[inlen - 1] == '\n') {
	inbufp[inlen - 1] = '\0';
	inlen--;
      }
      outbuf = calloc(1, inlen);
      outlen = convert(inbufp, outbuf, inlen);
      write(1, outbuf, outlen);
      free(outbuf);
    }
  }
}
