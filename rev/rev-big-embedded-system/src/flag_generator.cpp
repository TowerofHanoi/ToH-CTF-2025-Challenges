#include <iostream>
#include <algorithm>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>

using namespace std;

void flag()
{
	string line;
	vector<string> page;
	while(getline(cin,line)) page.push_back(line);
	//Don't print the whole file, only the first line so people can't
	//just run the program and get the flag, they have to either
	//attach with GDB and dump the flag from memory or reverse the code
	//and get the pastebin themselves
	//for(size_t i=0;i<page.size();i++) cout<<page[i]<<'\n';
	for(int i=0;i<min<int>(1,page.size());i++) cout<<page[i]<<'\n';
}

//Just the bare minimum obfuscation to not let people solve
//the challenge by just running strings on the binary.
//This challenge is supposed to be easy
//Function should return the following strings
//val(0)="wget"
//val(1)="-q"
//val(2)="-S"
//val(3)="-O"
//val(4)="-"
//val(5)="https://pastebin.com/raw/bU92ZVyV"
const char *val(int index)
{
	volatile char temp[128]; //Disable compiler optimizations
	memset((void*)temp,0,sizeof(temp));
	int i=0;
	switch(index)
	{
		case 0:
			temp[0]='w';
			temp[1]='g';
			temp[2]='e';
			temp[3]='t';
			break;
		case 1:
			temp[0]='-';
			temp[1]='q';
			break;
		case 2:
			temp[0]='-';
			temp[1]='S';
			break;
		case 3:
			temp[0]='-';
			temp[1]='O';
			break;
		case 4:
			temp[0]='-';
			break;
		case 5:
			temp[i++]='h';
			temp[i++]='t';
			temp[i++]='t';
			temp[i++]='p';
			temp[i++]='s';
			temp[i++]=':';
			temp[i++]='/';
			temp[i++]='/';
			temp[i++]='p';
			temp[i++]='a';
			temp[i++]='s';
			temp[i++]='t';
			temp[i++]='e';
			temp[i++]='b';
			temp[i++]='i';
			temp[i++]='n';
			temp[i++]='.';
			temp[i++]='c';
			temp[i++]='o';
			temp[i++]='m';
			temp[i++]='/';
			temp[i++]='r';
			temp[i++]='a';
			temp[i++]='w';
			temp[i++]='/'; 
			temp[i++]='b';
			temp[i++]='U';
			temp[i++]='9';
			temp[i++]='2';
			temp[i++]='Z';
			temp[i++]='V';
			temp[i++]='y';
			temp[i++]='V';
			break;
	}
	return strdup((char*)temp); //Yes, we leak some memory, but we execve after that...
}

int main()
{
	int fds[2];
	pipe(fds);
	pid_t pid=fork();
	if(pid<0) return 1;
	if(pid==0)
	{
		close(fds[0]); //Read end not needed
		close(STDOUT_FILENO);
		dup2(fds[1],STDOUT_FILENO); //Stdout redirected to pipe
		close(fds[1]);
		close(STDERR_FILENO); //Prevent wget from printing to stderr
		execlp(val(0),val(0),val(1),val(2),val(3),val(4),val(5),nullptr);
		return 1;
	}
	close(fds[1]); //Write end not needed
	close(STDIN_FILENO);
	dup2(fds[0],STDIN_FILENO); //Stdin redirected from pipe
	close(fds[0]);
	flag();
	return 0;
}
