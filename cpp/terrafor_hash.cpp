#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
int main(int argc,char**argv){
 if(argc!=2){std::cerr<<"Usage: cthash <file>\n";return 2;}
 std::ifstream f(argv[1],std::ios::binary); if(!f){return 1;}
 uint64_t h=14695981039346656037ULL; char c;
 while(f.get(c)){h^=(unsigned char)c;h*=1099511628211ULL;}
 std::cout<<std::hex<<std::setw(16)<<std::setfill('0')<<h<<"\n";
}
