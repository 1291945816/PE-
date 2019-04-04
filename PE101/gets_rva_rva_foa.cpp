#include "pe_widget.h"
#include "ui_pe_widget.h"
#include"header.h"
#include"dialog.h"
#include"dialog1.h"
#include"dialog2.h"
#include"dialog3.h"
#include<stdio.h>
#include<stdlib.h>
extern int  identify;
extern long int OPfileoffset;

extern int i;  //这是区块的数量

extern IMAGE_SECTION_HEADER section_header1[100];     //用于存放各区块 单独对区块的分析

int Gets_RVA(int fp,int t){
   if(identify == 32)
   {
      IMAGE_OPTIONAL_HEADER32 option_header;
      _lseek(fp,OPfileoffset,0);
      _read(fp,&option_header,sizeof (option_header));
      if(option_header.DataDirectory[t].Size != 0)  //如果大小不为0  说明该数据存在
      {
          return option_header.DataDirectory[t].VirtualAddress;  //获取块的虚拟地址
      }else
      {
          return 0;
      }
   }else if(identify == 64)
   {
       IMAGE_OPTIONAL_HEADER64 option_header;

       _lseek(fp,OPfileoffset,0);
       _read(fp,&option_header,sizeof (option_header));
       if(option_header.DataDirectory[t].Size != 0)  //如果大小不为0  说明该数据存在
       {
           return option_header.DataDirectory[t].VirtualAddress;  //获取块的虚拟地址
       }else
       {
           return 0;
       }
   }


}



//这是一个将得到的虚拟地址转化为FOA （文件偏移地址）
int  Gets_FOA( int adress){
    int  max,min;
    int  RVA2,offest = -1;
 if(adress != 0)   //虚拟地址为0也不必去遍历了
 {
    for(int j = 0;j < i;j++)
    {
        max = section_header1[j].VirtualAddress+section_header1[j].SizeOfRawData;
        min = section_header1[j].VirtualAddress;
        if(adress >= min && adress <= max)
        {
            RVA2 = adress - min;
            offest = RVA2 + section_header1[j].PointerToRawData;

            break;
        }


    }

 }
  return offest;


};
