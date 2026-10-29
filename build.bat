g++ -O2 -std=c++17 -static -o zoompatch.exe zoompatch.cpp
rem zoompatch.exe elementclient_64.exe            (dry run, changes nothing)
rem zoompatch.exe elementclient_64.exe --apply    (writes elementclient_64.exe.bak once, then patches)
rem zoompatch.exe elementclient_64.exe --revert   (flips the byte back to 76)