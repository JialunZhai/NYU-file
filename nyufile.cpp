#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <vector>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/sha.h>

using namespace std;

using Status=unsigned char;
constexpr Status FAIL_NONE=0,SUCC_SINGLE=1,FAIL_MUTI=2,SUCC_SHA1=3;
constexpr size_t FILENAME_LEN=11; // 8+3 ('\0' no count) and no '/' in filename implies filename is pathname
constexpr unsigned SHA1_LEN=20;

#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

bool char2Hex(unsigned char &c);
bool eqN(const unsigned char* const &addr1,const unsigned char* const &addr2,const size_t &n);
const struct BootEntry& readBootEntry(const unsigned char* const &disk);
const struct DirEntry& readDirEntry(const unsigned char* const &addr);
void printUsage();
void printFSInfo(const unsigned char* const &disk);
void printName(const unsigned char* const &name);
void printRootDir(const unsigned char* const &disk);
void printStatus(const unsigned char* const &filename,const Status& status);
bool parseCMD(const int &argc,char* const argv[]);
Status recoverUnique(unsigned char* const &disk,const unsigned char* const &filename);
Status recoverMulti(unsigned char* const &disk,const unsigned char* const &filename,const unsigned char* const &sha1);
Status recoverRandom(unsigned char* const &disk,const unsigned char* const &filename,const unsigned char* const &sha1);
map<unsigned,bool> getUnusedClusId(const unsigned &first_clus_id,const unsigned &last_clus_id,const unsigned* const &fat_area);
bool checkClusIdSeq(const unsigned char* const &disk,const unsigned char* const &sha1,const unsigned &file_sz,const vector<unsigned> &clus_id_seq);
bool dfsUnusedClusId(const unsigned char* const &disk,const unsigned char* const &sha1,const unsigned &file_sz,const unsigned &clus_num,map<unsigned,bool> &visited,vector<unsigned> &clus_id_seq);

int main(int argc,char* argv[]){
    if(!parseCMD(argc,argv)) printUsage();
}

bool char2Hex(unsigned char &c){
    if(isalpha(c)){
        c=tolower(c);
        if(c>'f') return false;
        c=c-'a'+10;
    }
    else if(isdigit(c)) c-='0';
    else return false;
    return true;
}

bool eqN(const unsigned char* const &addr1,const unsigned char* const &addr2,const size_t &n){
    for(size_t i=0;i!=n;++i)
        if(addr1[i]!=addr2[i]) return false;
    return true;
}

const struct BootEntry& readBootEntry(const unsigned char* const &disk){
    return *(const struct BootEntry*)disk;
}

const struct DirEntry& readDirEntry(const unsigned char* const &addr){
    return *(const struct DirEntry*)addr;
}

void printUsage(){
    printf("Usage: ./nyufile disk <options>\n"
           "  -i                     Print the file system information.\n"
           "  -l                     List the root directory.\n"
           "  -r filename [-s sha1]  Recover a contiguous file.\n"
           "  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

void printFSInfo(const unsigned char* const &disk){
    const struct BootEntry &boot_entry=readBootEntry(disk);
    printf("Number of FATs = %d\n",boot_entry.BPB_NumFATs);
    printf("Number of bytes per sector = %d\n",boot_entry.BPB_BytsPerSec);
    printf("Number of sectors per cluster = %d\n",boot_entry.BPB_SecPerClus);
    printf("Number of reserved sectors = %d\n",boot_entry.BPB_RsvdSecCnt);
}

void printName(const unsigned char* const &name){
    int n=7;
    while(n>=0&&name[n]==' ') --n;
    for(int k=0;k<=n;++k) printf("%c",name[k]);
    n=10;
    while(n>=8&&name[n]==' ') --n;
    if(n>=8) printf(".");
    for(int k=8;k<=n;++k) printf("%c",name[k]);
}

void printRootDir(const unsigned char* const &disk){
    const struct BootEntry &boot_entry=readBootEntry(disk);
    const unsigned char* const data_area=disk+(boot_entry.BPB_RsvdSecCnt+boot_entry.BPB_NumFATs*boot_entry.BPB_FATSz32)*boot_entry.BPB_BytsPerSec;
    unsigned* const fat_area=(unsigned*)(disk+boot_entry.BPB_RsvdSecCnt*boot_entry.BPB_BytsPerSec);
    struct DirEntry dir_entry;
    unsigned valid_entry_cnt=0;
    const unsigned N=boot_entry.BPB_SecPerClus*boot_entry.BPB_BytsPerSec/sizeof(dir_entry);
    for(unsigned clus_id=boot_entry.BPB_RootClus&0x0fffffff;clus_id<0x0ffffff8;clus_id=fat_area[clus_id]&0x0fffffff){
        const unsigned char* addr=data_area+(clus_id-2)*boot_entry.BPB_SecPerClus*boot_entry.BPB_BytsPerSec;
        for(unsigned i=0;i!=N;++i){
            dir_entry=readDirEntry(addr+i*sizeof(dir_entry));
            if(dir_entry.DIR_Name[0]==0xe5||dir_entry.DIR_Name[0]==0x00||dir_entry.DIR_Attr==0x0f) continue; // skip removed entry, unused entry and LFN entry
            ++valid_entry_cnt;
            printName(dir_entry.DIR_Name);
            if(dir_entry.DIR_Attr==0x10) printf("/");
            printf(" (size = %d, starting cluster = %d)\n",dir_entry.DIR_FileSize,(dir_entry.DIR_FstClusHI<<16)|dir_entry.DIR_FstClusLO);
        }
    }
    printf("Total number of entries = %d\n",valid_entry_cnt);
}

void printStatus(const unsigned char* const &filename,const Status& status){
    printName(filename);
    switch(status){
        case FAIL_NONE: printf(": file not found\n"); break;
        case SUCC_SINGLE: printf(": successfully recovered\n"); break;
        case FAIL_MUTI: printf(": multiple candidates found\n"); break;
        case SUCC_SHA1: printf(": successfully recovered with SHA-1\n"); break;
        default: break;
    }
}

bool parseCMD(const int &argc,char* const argv[]){ // return false iff grammar is incorrect 
    unsigned char filename[FILENAME_LEN+3]={'\0'}; // 8+'.'+3+'\0'
    unsigned char sha1[SHA1_LEN+1]={'\0'};
    bool opt_i=false,opt_l=false,opt_r=false,opt_R=false,opt_s=false;
    int ch=-1;
    while((ch=getopt(argc,argv,"ilr:R:s:"))!=-1){
        switch(ch){
            case 'i': // Print the file system information.
                if(opt_i) return false;
                else opt_i=true;
                break;
            case 'l': // List the root directory.
                if(opt_l) return false;
                else opt_l=true;
                break;
            case 'r': // Recover a contiguous file.
                if(opt_r) return false;
                else opt_r=true;
                if(strlen(optarg)>FILENAME_LEN+1) return false; // "+1" means '.', long filename
                strcpy((char*)filename,optarg);
                break;
            case 'R': // Recover a possibly non-contiguous file.
                if(opt_R) return false;
                else opt_R=true;
                if(strlen(optarg)>FILENAME_LEN+1) return false; // "+1" means '.', long filename
                strcpy((char*)filename,optarg);
                break;
            case 's': // SHA-1 message digest 
                if(opt_s) return false;
                else opt_s=true;
                if(strlen(optarg)!=SHA1_LEN*2) return false; // invalid sha1 length
                for(unsigned i=0;i!=SHA1_LEN;++i){
                    unsigned char c_high=optarg[i*2];
                    if(!char2Hex(c_high)) return false;
                    unsigned char c_low=optarg[i*2+1];
                    if(!char2Hex(c_low)) return false;
                    sha1[i]=(c_high<<4)|c_low;
                }
                break;
            default:
                return false;
        }
    }
    // check grammar
    if(opt_i+opt_l+opt_r+opt_R!=1) return false;
    if((opt_i||opt_l)&&opt_s) return false; // -i or -l, but -s
    if(opt_R&&!opt_s) return false; // -R, but no -s
    // open and map disk-file
    int fd_disk=-1;
    if(optind+1!=argc||(fd_disk=open(argv[optind],O_RDWR))==-1) return false; // non-option arg#!=1 or invalid disk file
    struct stat stat_disk_file;
    stat(argv[optind],&stat_disk_file);
    unsigned long disk_file_sz=stat_disk_file.st_size;
    unsigned char* disk=NULL;
    if(!(disk=(unsigned char*)mmap(NULL,disk_file_sz,PROT_READ|PROT_WRITE,MAP_SHARED,fd_disk,0))){
        perror(strerror(errno));
        exit(0);
    }
    // convert filename from 8'.'3 to 83'\0' format
    if(opt_r||opt_R){
        unsigned char* ptr_c=(unsigned char*)strrchr((char*)filename,'.');
        if(ptr_c){
            unsigned char prefix[8]={' ',' ',' ',' ',' ',' ',' ',' '};
            unsigned char surfix[3]={' ',' ',' '};
            for(size_t i=0;filename+i!=ptr_c;++i) prefix[i]=filename[i];
            for(size_t i=0;ptr_c[1+i]!='\0';++i) surfix[i]=ptr_c[1+i];
            for(size_t i=0;i!=8;++i) filename[i]=prefix[i];
            for(size_t i=0;i!=3;++i) filename[8+i]=surfix[i];
            filename[FILENAME_LEN]='\0';
        }
        else{
            for(size_t i=strlen((char*)filename);i<FILENAME_LEN;++i) filename[i]=' ';
            filename[FILENAME_LEN]='\0';
        }
    }
    // run
    if(opt_i) printFSInfo(disk);
    if(opt_l) printRootDir(disk);
    if(opt_r){
        if(!opt_s) printStatus(filename,recoverUnique(disk,filename));
        else printStatus(filename,recoverMulti(disk,filename,sha1));
    }
    if(opt_R) printStatus(filename,recoverRandom(disk,filename,sha1));
    return true;
}

Status recoverUnique(unsigned char* const &disk,const unsigned char* const &filename){
    const struct BootEntry &boot_entry=readBootEntry(disk);
    unsigned char* const data_area=disk+(boot_entry.BPB_RsvdSecCnt+boot_entry.BPB_NumFATs*boot_entry.BPB_FATSz32)*boot_entry.BPB_BytsPerSec;
    unsigned* const fat_area=(unsigned*)(disk+boot_entry.BPB_RsvdSecCnt*boot_entry.BPB_BytsPerSec);
    struct DirEntry dir_entry;
    const unsigned bytes_per_clus=boot_entry.BPB_SecPerClus*boot_entry.BPB_BytsPerSec;
    const unsigned N=bytes_per_clus/sizeof(dir_entry);
    // check whether it contains unique possible file
    struct DirEntry *ptr_target_entry=NULL;
    for(unsigned clus_id=boot_entry.BPB_RootClus&0x0fffffff;clus_id<0x0ffffff8;clus_id=fat_area[clus_id]&0x0fffffff){ // for each cluster of root dir
        unsigned char* addr=data_area+(clus_id-2)*bytes_per_clus; // addr points to the beginning of current cluster of root dir
        for(unsigned i=0;i!=N;++i){ // for each entry in current cluster of root dir
            dir_entry=readDirEntry(addr+i*sizeof(dir_entry));
            if(dir_entry.DIR_Name[0]==0x00||dir_entry.DIR_Attr==0x0f||dir_entry.DIR_Attr==0x10) continue; // skip unused entry, directory and LFN entry
            if(dir_entry.DIR_Name[0]==0xe5){ // this is a removed entry
                if(eqN(filename+1,dir_entry.DIR_Name+1,FILENAME_LEN-1)){
                    if(ptr_target_entry) return FAIL_MUTI;
                    else ptr_target_entry=(struct DirEntry *)(addr+i*sizeof(dir_entry));
                }
            }
        }
        if(clus_id==0x0ffffff8) break;
    }
    if(!ptr_target_entry) return FAIL_NONE;
    // recover
    ptr_target_entry->DIR_Name[0]=filename[0];
    if(ptr_target_entry->DIR_FileSize==0) return SUCC_SINGLE; // empty file
    const unsigned clus_num=ptr_target_entry->DIR_FileSize/bytes_per_clus+(bool)(ptr_target_entry->DIR_FileSize%bytes_per_clus);
    // change all FATs
    const unsigned tol_sec_num=boot_entry.BPB_TotSec16>boot_entry.BPB_TotSec32?boot_entry.BPB_TotSec16:boot_entry.BPB_TotSec32;
    const unsigned clus_id_max=(tol_sec_num-boot_entry.BPB_RsvdSecCnt-boot_entry.BPB_NumFATs*boot_entry.BPB_FATSz32)/boot_entry.BPB_SecPerClus+2-1;
    const unsigned first_clus_id=((ptr_target_entry->DIR_FstClusHI<<16)|ptr_target_entry->DIR_FstClusLO)&0x0fffffff;
    if(first_clus_id+clus_num-1>clus_id_max) return FAIL_NONE;
        // the remaining area cannot contain the file, this file cannot be contiguous
        // this file cannot be the target file
    for(unsigned char fat_id=0;fat_id!=boot_entry.BPB_NumFATs;++fat_id){ // for each FAT
        unsigned* cur_fat=(unsigned*)(disk+(boot_entry.BPB_RsvdSecCnt+fat_id*boot_entry.BPB_FATSz32)*boot_entry.BPB_BytsPerSec);
        for(unsigned i=0;i+1<clus_num;++i) cur_fat[first_clus_id+i]=first_clus_id+i+1;
        cur_fat[first_clus_id+clus_num-1]=0x0ffffff8;
    }
    return SUCC_SINGLE;
}

Status recoverMulti(unsigned char* const &disk,const unsigned char* const &filename,const unsigned char* const &sha1){
    const struct BootEntry &boot_entry=readBootEntry(disk);
    unsigned char* const data_area=disk+(boot_entry.BPB_RsvdSecCnt+boot_entry.BPB_NumFATs*boot_entry.BPB_FATSz32)*boot_entry.BPB_BytsPerSec;
    unsigned* const fat_area=(unsigned*)(disk+boot_entry.BPB_RsvdSecCnt*boot_entry.BPB_BytsPerSec);
    struct DirEntry dir_entry;
    const unsigned bytes_per_clus=boot_entry.BPB_SecPerClus*boot_entry.BPB_BytsPerSec;
    const unsigned N=bytes_per_clus/sizeof(dir_entry);
    const unsigned tol_sec_num=boot_entry.BPB_TotSec16>boot_entry.BPB_TotSec32?boot_entry.BPB_TotSec16:boot_entry.BPB_TotSec32;
    const unsigned clus_id_max=(tol_sec_num-boot_entry.BPB_RsvdSecCnt-boot_entry.BPB_NumFATs*boot_entry.BPB_FATSz32)/boot_entry.BPB_SecPerClus+2-1;
    // check whether it contains the file
    struct DirEntry *ptr_target_entry=NULL;
    for(unsigned clus_id=boot_entry.BPB_RootClus&0x0fffffff;clus_id<0x0ffffff8;clus_id=fat_area[clus_id]&0x0fffffff){ // for each cluster of root dir
        unsigned char* addr=data_area+(clus_id-2)*bytes_per_clus; // addr points to the beginning of current cluster of root dir
        for(unsigned i=0;i!=N;++i){ // for each entry in current cluster of root dir
            dir_entry=readDirEntry(addr+i*sizeof(dir_entry));
            if(dir_entry.DIR_Name[0]==0x00||dir_entry.DIR_Attr==0x0f||dir_entry.DIR_Attr==0x10) continue; // skip unused entry, directory and LFN entry
            if(dir_entry.DIR_Name[0]==0xe5){
                if(eqN(filename+1,dir_entry.DIR_Name+1,FILENAME_LEN-1)){
                    unsigned char cur_sha1[SHA1_LEN+1]={0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09,'\0'};
                    // initialize cur_sha1 to be the sha1 of empty file
                    if(dir_entry.DIR_FileSize!=0){ // if the file is not empty, then compute its sha1
                        const unsigned first_clus_id=((dir_entry.DIR_FstClusHI<<16)|dir_entry.DIR_FstClusLO)&0x0fffffff;
                        const unsigned clus_num=dir_entry.DIR_FileSize/bytes_per_clus+(bool)(dir_entry.DIR_FileSize%bytes_per_clus);
                        if(first_clus_id+clus_num-1>clus_id_max) continue;
                        // the remaining area cannot contain the file, this file cannot be contiguous
                        // this file cannot be the target file, try next entry
                        const unsigned char* file_content=data_area+(first_clus_id-2)*bytes_per_clus;
                        SHA1(file_content,dir_entry.DIR_FileSize,cur_sha1);
                    }
                    if(eqN(sha1,cur_sha1,SHA1_LEN)){
                        ptr_target_entry=(struct DirEntry *)(addr+i*sizeof(dir_entry));
                        clus_id=0x0ffffff8;
                        break;
                    }
                }
            }
        }
        if(clus_id==0x0ffffff8) break;
    }
    if(!ptr_target_entry) return FAIL_NONE;
    // recover
    ptr_target_entry->DIR_Name[0]=filename[0];
    if(ptr_target_entry->DIR_FileSize==0) return SUCC_SHA1; // empty file
    unsigned clus_num=ptr_target_entry->DIR_FileSize/bytes_per_clus+(bool)(ptr_target_entry->DIR_FileSize%bytes_per_clus);
    // change all FATs
    unsigned first_clus_id=((ptr_target_entry->DIR_FstClusHI<<16)|ptr_target_entry->DIR_FstClusLO)&0x0fffffff;
    for(unsigned char fat_id=0;fat_id!=boot_entry.BPB_NumFATs;++fat_id){
        unsigned* cur_fat=(unsigned*)(disk+(boot_entry.BPB_RsvdSecCnt+fat_id*boot_entry.BPB_FATSz32)*boot_entry.BPB_BytsPerSec);
        for(unsigned i=0;i+1<clus_num;++i) cur_fat[first_clus_id+i]=first_clus_id+i+1;
        cur_fat[first_clus_id+clus_num-1]=0x0ffffff8;
    }
    return SUCC_SHA1;
}

map<unsigned,bool> getUnusedClusId(const unsigned &first_clus_id,const unsigned &last_clus_id,const unsigned* const &fat_area){
    map<unsigned,bool> unused_clus_id; // use map other than unordered_map inorder to search contiguously first
    for(unsigned clus_id=first_clus_id;clus_id<=last_clus_id;++clus_id)
        if((fat_area[clus_id]&0x0fffffff)==0) unused_clus_id[clus_id]=false;
    return unused_clus_id;
}

bool checkClusIdSeq(const unsigned char* const &disk,const unsigned char* const &sha1,const unsigned &file_sz,const vector<unsigned> &clus_id_seq){
    const struct BootEntry &boot_entry=readBootEntry(disk);
    const unsigned char* const data_area=disk+(boot_entry.BPB_RsvdSecCnt+boot_entry.BPB_NumFATs*boot_entry.BPB_FATSz32)*boot_entry.BPB_BytsPerSec;
    unsigned char* const file_buf=(unsigned char*)malloc(file_sz);
    const unsigned bytes_per_clus=boot_entry.BPB_SecPerClus*boot_entry.BPB_BytsPerSec;
    unsigned char* dst=NULL;
    const unsigned char* src=NULL;
    for(unsigned i=0;i!=clus_id_seq.size();++i){
        dst=file_buf+i*bytes_per_clus;
        src=data_area+(clus_id_seq[i]-2)*bytes_per_clus;
        if(i+1!=clus_id_seq.size()) memcpy(dst,src,bytes_per_clus);
        else memcpy(dst,src,file_sz-i*bytes_per_clus);
    }
    unsigned char cur_sha1[SHA1_LEN+1]={'\0'};
    SHA1(file_buf,file_sz,cur_sha1);
    free(file_buf);
    return eqN(cur_sha1,sha1,SHA1_LEN);
}

bool dfsUnusedClusId(const unsigned char* const &disk,const unsigned char* const &sha1,const unsigned &file_sz,const unsigned &clus_num,map<unsigned,bool> &visited,vector<unsigned> &clus_id_seq){
    if(clus_id_seq.size()==clus_num) return checkClusIdSeq(disk,sha1,file_sz,clus_id_seq);
    for(auto iter=visited.begin();iter!=visited.end();++iter){ // back-trace algorithm
        if(iter->second) continue; // if this cluster has been visited, then skip it
        iter->second=true;
        clus_id_seq.push_back(iter->first);
        if(dfsUnusedClusId(disk,sha1,file_sz,clus_num,visited,clus_id_seq)) return true;
        clus_id_seq.pop_back();
        iter->second=false;
    }
    return false;
}

Status recoverRandom(unsigned char* const &disk,const unsigned char* const &filename,const unsigned char* const &sha1){
    const struct BootEntry &boot_entry=readBootEntry(disk);
    unsigned char* const data_area=disk+(boot_entry.BPB_RsvdSecCnt+boot_entry.BPB_NumFATs*boot_entry.BPB_FATSz32)*boot_entry.BPB_BytsPerSec;
    unsigned* const fat_area=(unsigned*)(disk+boot_entry.BPB_RsvdSecCnt*boot_entry.BPB_BytsPerSec);
    struct DirEntry dir_entry;
    const unsigned bytes_per_clus=boot_entry.BPB_SecPerClus*boot_entry.BPB_BytsPerSec;
    const unsigned N=bytes_per_clus/sizeof(dir_entry);
    const unsigned tol_sec_num=boot_entry.BPB_TotSec16>boot_entry.BPB_TotSec32?boot_entry.BPB_TotSec16:boot_entry.BPB_TotSec32;
    const unsigned clus_id_max=(tol_sec_num-boot_entry.BPB_RsvdSecCnt-boot_entry.BPB_NumFATs*boot_entry.BPB_FATSz32)/boot_entry.BPB_SecPerClus+2-1;
    map<unsigned,bool> visited=getUnusedClusId(2,(11<clus_id_max?11:clus_id_max),fat_area);
    vector<unsigned> clus_id_seq;
    struct DirEntry *ptr_target_entry=NULL;
    for(unsigned clus_id=boot_entry.BPB_RootClus&0x0fffffff;clus_id<0x0ffffff8;clus_id=fat_area[clus_id]&0x0fffffff){ // for each cluster of root dir
        unsigned char* addr=data_area+(clus_id-2)*bytes_per_clus; // addr points to the beginning of current cluster of root dir
        for(unsigned i=0;i!=N;++i){ // for each entry in current cluster of root dir
            dir_entry=readDirEntry(addr+i*sizeof(dir_entry));
            if(dir_entry.DIR_Name[0]==0x00||dir_entry.DIR_Attr==0x0f||dir_entry.DIR_Attr==0x10) continue; // skip unused entry, directory and LFN entry
            if(dir_entry.DIR_Name[0]==(unsigned char)0xe5){
                if(eqN(filename+1,dir_entry.DIR_Name+1,FILENAME_LEN-1)){
                    if(dir_entry.DIR_FileSize!=0){ // if the file is not empty
                        const unsigned clus_num=dir_entry.DIR_FileSize/bytes_per_clus+(bool)(dir_entry.DIR_FileSize%bytes_per_clus);
                        if(visited.size()<clus_num) continue;
                        // the unused area in 2-11 clusters cannot contain the file,
                        // this file cannot be the target file, try next entry
                        const unsigned first_clus_id=((dir_entry.DIR_FstClusHI<<16)|dir_entry.DIR_FstClusLO)&0x0fffffff;
                        if(first_clus_id>11) continue; // first cluser of this file is out of range, in other words, it is not entirely in cluster 2-11, skip
                        clus_id_seq.push_back(first_clus_id);
                        if(dfsUnusedClusId(disk,sha1,dir_entry.DIR_FileSize,clus_num,visited,clus_id_seq)){
                            ptr_target_entry=(struct DirEntry *)(addr+i*sizeof(dir_entry));
                            clus_id=0x0ffffff8;
                            break;
                        }
                        else clus_id_seq.pop_back();
                    }
                    else{ //if the file is empty
                        unsigned char cur_sha1[SHA1_LEN+1]={0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09,'\0'};
                        //initialize cur_sha1 to be the sha1 of empty file
                        if(eqN(sha1,cur_sha1,SHA1_LEN)){
                            ptr_target_entry=(struct DirEntry *)(addr+i*sizeof(dir_entry));
                            clus_id=0x0ffffff8;
                            break;
                        }
                    }
                }
            }
        }
        if(clus_id==0x0ffffff8) break;
    }
    if(!ptr_target_entry) return FAIL_NONE;
    // recover
    ptr_target_entry->DIR_Name[0]=filename[0];
    if(ptr_target_entry->DIR_FileSize==0) return SUCC_SHA1; // empty file
    // change all FATs
    const unsigned first_clus_id=((ptr_target_entry->DIR_FstClusHI<<16)|ptr_target_entry->DIR_FstClusLO)&0x0fffffff;
    for(unsigned char fat_id=0;fat_id!=boot_entry.BPB_NumFATs;++fat_id){
        unsigned* cur_fat=(unsigned*)(disk+(boot_entry.BPB_RsvdSecCnt+fat_id*boot_entry.BPB_FATSz32)*boot_entry.BPB_BytsPerSec);
        for(unsigned i=0;i+1<clus_id_seq.size();++i) cur_fat[clus_id_seq[i]]=clus_id_seq[i+1];
        cur_fat[clus_id_seq.back()]=0x0ffffff8;
    }
    return SUCC_SHA1;
}