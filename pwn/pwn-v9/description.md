## v9

Bored about the usual v8 browser exploitation? Try the new version: v9!

Oh... You thought that it was some new JS interpreter? No, no, no. It's the brand new vim9! (It was brand new when I wrote this challenge)

Also, since I thought that exiting vim the usual ":qa!" way was too easy, I made it impossible to get out.
Good luck!

Note: take [this](https://github.com/TeamItaly/TeamItalyCTF-2023/tree/master/colon-q-exclamation-mark), you might need it ;)

stty raw -echo; nc ... 12321; stty raw sane
