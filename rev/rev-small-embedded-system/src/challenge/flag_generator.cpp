
#include <string>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>

using namespace std;

// Avoid using printf / puts as this is a statically linked binary and a lot
// of code would be pulled into the binary. Trying to be kind to whoever will
// reverse this code, don't want them to get lost reversing the inner working
// of printf. Unfortunately there's no easy was to also avoid pulling in
// malloc/free, and a large portion of the binary will thus be Newlib's
// implementation of these 2 functions...
void write_stderr(const char *s)
{
    write(2,s,strlen(s));
    write(2,"\n",1);
}

void generate_flag(const string& input)
{
#ifdef _MIOSIX
    //Make sure we're running from a writable filesystem
    chdir("/sd");
#endif

    //Find all the vocals in the string and write them in the temp file.
    //File is only used so the algorithm is tied to some syscall that will need
    //to be identified as the syscall numbers in Miosix are not the same as Linux
    int fd=open("aeiou",O_RDWR | O_CREAT,0660);
    for(size_t dex=0;;)
    {
        dex=input.find_first_of("aeiou",dex);
        if(dex==string::npos) break;
        write(fd,&input[dex++],1);
    }

    //Rewind file and read back the vocals found. For each of them do a
    //"convolution-like" moltiplication of it by every character in the original
    //string and keep only the char that match the toh flag regex
    lseek(fd,0,SEEK_SET);
    string flag="toh{";
    for(;;)
    {
        char c;
        if(read(fd,&c,1)!=1) break;
        for(size_t i=0;i<input.length();i++)
        {
            char cc=c*input[i];
            if((cc>='0' && cc<='9') ||
               (cc>='a' && cc<='z') ||
               (cc>='A' && cc<='Z') ||
               cc=='-' || cc=='_' || cc=='?' || cc=='!') flag+=cc;
        }
    }
    flag+="}";
    close(fd);
    unlink("aeiou");

    //Finally write the flag to file
    int fd2=open("flag.txt",O_WRONLY | O_CREAT,0660);
    write(fd2,flag.data(),flag.length());
    close(fd2);
}

void usage()
{
    write_stderr("flag_generator requires either 0 or 1 command line parameter");
    exit(1);
}

int main(int argc, char *argv[])
{
    if(argc!=1 && argc!=2) usage();

    if(argc==1)
    {
        static const char *args[] = { "/bin/flag_generator", "Your flag.txt is ready", nullptr };
        static const char *envs[] = { nullptr };
        execve(args[0],(char*const*)args,(char*const*)envs);
        return 1;
    }

    write_stderr("flag_generator starting on stm32h755...");

    generate_flag(argv[1]);

    write_stderr("Your flag.txt is ready");
    return 0;
}
