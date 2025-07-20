//Morse code encode by fede.tft GPL v3

#include <iostream>
#include <vector>
#include <string>

using namespace std;

vector<vector<bool>> letters=
{
    {0,1},     //A
    {1,0,0,0}, //B
    {1,0,1,0}, //C
    {1,0,0},   //D
    {0},       //E
    {0,0,1,0}, //F
    {1,1,0},   //G
    {0,0,0,0}, //H
    {0,0},     //I
    {0,1,1,1}, //J
    {1,0,1},   //K
    {0,1,0,0}, //L
    {1,1},     //M
    {1,0},     //N
    {1,1,1},   //O
    {0,1,1,0}, //P
    {1,1,0,1}, //Q
    {0,1,0},   //R
    {0,0,0},   //S
    {1},       //T
    {0,0,1},   //U
    {0,0,0,1}, //V
    {0,1,1},   //W
    {1,0,0,1}, //X
    {1,0,1,1}, //Y
    {1,1,0,0}  //Z
};

vector<vector<bool>> numbers=
{
    {1,1,1,1,1}, //0
    {0,1,1,1,1}, //1
    {0,0,1,1,1}, //2
    {0,0,0,1,1}, //3
    {0,0,0,0,1}, //4
    {0,0,0,0,0}, //5
    {1,0,0,0,0}, //6
    {1,1,0,0,0}, //7
    {1,1,1,0,0}, //8
    {1,1,1,1,0}  //9
};

const int dot=50; //Dot duration in milliseconds
const int dash=3*dot;

int main()
{
    string s;
    getline(cin,s);

    for(char c : s)
    {
        if(isalpha(c))
        {
            auto letter=letters.at(c-'a');
            for(auto bit : letter)
            {
                //cout<<(bit ? '-' : '.');
                cout<<"pulse("<<(bit ? dash : dot)<<");\n";
                cout<<"sleepMs("<<dot<<");\n";
            }
            // cout<<'\n';
            cout<<"sleepMs("<<2*dot<<");\n"; //Extend pause to dash between letters
        } else if(isdigit(c)) {
            auto number=numbers.at(c-'0');
            for(auto bit : number)
            {
                //cout<<(bit ? '-' : '.');
                cout<<"pulse("<<(bit ? dash : dot)<<");\n";
                cout<<"sleepMs("<<dot<<");\n";
            }
            // cout<<'\n';
            cout<<"sleepMs("<<2*dot<<");\n"; //Extend pause to dash between letters
        } else abort();
    }
}
