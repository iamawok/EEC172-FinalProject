
/* These functions are based on the Arduino test program at
*  https://github.com/adafruit/Adafruit-SSD1351-library/blob/master/examples/test/test.ino
*
*  You can use these high-level routines to implement your
*  test program.
*/

#include "Adafruit_GFX.h"
#include "Adafruit_SSD1351.h"

#ifndef __ADA_TEST__
#define __ADA_TEST__

//*****************************************************************************
extern void delay(unsigned long ulCount);
extern void testfastlines(unsigned int color1, unsigned int color2);
extern void testdrawrects(unsigned int color);
extern void testfillrects(unsigned int color1, unsigned int color2);
extern void testfillcircles(unsigned char radius, unsigned int color);
extern void testdrawcircles(unsigned char radius, unsigned int color);
extern void testtriangles();
extern void testroundrects();
extern void testlines(unsigned int color);
extern void lcdTestPattern(void);
extern void lcdTestPattern2(void);
//*****************************************************************************

#endif
