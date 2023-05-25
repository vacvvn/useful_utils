#define DEBUGOUT	printf
#define EOL "\n"

int hexDump(char *desc, void *addr, int len)
{   // 0 must always be returned
    int i;
    unsigned char buff[24];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if(desc) DEBUGOUT ("%s:" EOL, desc);

    if(!len)
    {
        DEBUGOUT("  ZERO LENGTH" EOL);
        return 0;
    }

    if (len < 0)
    {
        DEBUGOUT("  NEGATIVE LENGTH: %i" EOL, len);
        return 0;
    }

    // Process every byte in the data.
    for(i = 0; i < len; i++)
    {
        // Multiple of 16 means new line (with line offset).

        if(!(i & 15))
        {
            // Just don't print ASCII for the zeroth line.
            if (i != 0) DEBUGOUT("  %s" EOL, buff);

            // Output the offset.
             DEBUGOUT("  %04X ", i);
        }

        // Now the hex code for the specific character.
        DEBUGOUT(" %02X", pc[i]);

        // And store a printable ASCII character for later.
        buff[i & 15] = ((pc[i] < 0x20) || (pc[i] > 0x7e)) ? '.' : pc[i];
        buff[(i & 15) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while (i & 15)
    {
        DEBUGOUT("   ");
        i++;
    }

    // And print the final ASCII bit.
     DEBUGOUT("  %s" EOL, buff);

    return 0;
}

