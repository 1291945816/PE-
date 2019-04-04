#include "pe_widget.h"
#include "ui_pe_widget.h"
#include"header.h"
#include"dialog.h"
#include"dialog1.h"
#include"dialog2.h"
#include"dialog3.h"
#include<stdio.h>
#include<stdlib.h>
 int Gets_RVA(int fp,int t);


int Gets_FOA(int adress);

extern int k;  //一个标识  用来表示  是否按了开始分析的键
extern int identify;


void import_show(Ui::PE_Widget * ui,int fp){

    if(k == 1 && fp != -1)
    {
        _IMAGE_IMPORT_DESCRIPTOR import_descriptor;
        unsigned t = 0;
        unsigned int  number = 0;



        int RVA = 0; //数据目录表的RVA
        int FOA = 0;//文件偏移

        int FOA_Name = 0;  //与之关联的DLL文件名的文件偏移
        int FOA2 = 0;   //用于获取指向输入名称地址表的文件偏移
        int FOA3 = 0;
       char name[256];

       IMAGE_THUNK_DATA32  data32;
       IMAGE_THUNK_DATA64 data64;

        RVA = Gets_RVA(fp,1); //获取相对虚拟距离
        FOA = Gets_FOA(RVA); //获取文件偏移距离

        if(FOA != -1)
        {
            _lseek(fp,FOA,0); //偏移指定距离
            _read(fp,&import_descriptor,sizeof (import_descriptor));//从指定的偏移位置读取书数据

            char buffer[256];  //用来临时保存输出的数据

            ui->textEdit->append("---------import-------");
            while(import_descriptor.Name != 0)   //判断这个内容是否为空0也就是说 判断是否到达了该数组的后面（到该数组的后面 的话结构内容是全为0的）
            {
               FOA_Name = Gets_FOA(import_descriptor.Name);
               _lseek(fp,FOA_Name,0);
               _read(fp,name,sizeof (name));

               sprintf(buffer,"%s",name);
               QString str = QString(buffer);
               ui->textEdit->append(str);

               sprintf(buffer,"(RVA)name:%lx",import_descriptor.Name);
               str = QString(buffer);
               ui->textEdit->append(str);

               sprintf(buffer,"Characteristics:%lx",import_descriptor.Characteristics);
               str = QString(buffer);
               ui->textEdit->append(str);

               sprintf(buffer,"OriginalFirstThunk:%lx",import_descriptor.OriginalFirstThunk);
               str = QString(buffer);
               ui->textEdit->append(str);

               sprintf(buffer,"TimeDateStamp:%lx",import_descriptor.TimeDateStamp);
               str = QString(buffer);
               ui->textEdit->append(str);

               sprintf(buffer,"ForwarderChain:%lx",import_descriptor.ForwarderChain);
               str = QString(buffer);
               ui->textEdit->append(str);

               sprintf(buffer,"FirstThunk:%lx\n",import_descriptor.FirstThunk);
               str = QString(buffer);
               ui->textEdit->append(str);
             //获取输入地址表的函数的文件偏移地址
               FOA2 = Gets_FOA(import_descriptor.FirstThunk);
               _lseek(fp,FOA2,0);  //偏移到输入地址表的数组开头
               /*将32位和64位分开*/
               ui->textEdit->append(".Dll        hint            Fuction_name");
              if(identify == 32){
                   read(fp,&data32,sizeof (data32));  //读取内容
                   WORD Hint = 0;
                   char Name3[100]{'\0'};
                   unsigned j = 0;
                   while((data32.u1.AddressOfData) != NULL)  //判断是否为空 (最后面的结构内容是空的)
                   {
                        t = data32.u1.AddressOfData >> 31; //左移31位
                        number = data32.u1.AddressOfData & 0x7FFFFFFF;  //取剩下的31位数据
                        if(t == 1)
                        {


                            sprintf(buffer,"%s   %08X  ",name,number);  //如果没有函数名称  则以序号输出
                            str = QString(buffer);
                            ui->textEdit->append(str);
                        }else if(t == 0)
                        {
                            FOA3 = Gets_FOA(data32.u1.AddressOfData);  //获取内容
                             _lseek(fp,FOA3,0);
                             _read(fp,&Hint,sizeof (Hint)); //移动获取输入表函数的序号
                             _read(fp,Name3,sizeof (Name3));   //取出名字
                             sprintf(buffer,"%s   %04X   %s",name,Hint,Name3);
                             str = QString(buffer);
                             ui->textEdit->append(str);
                        }
                        FOA2 = FOA2+sizeof (data32);
                         _lseek(fp,FOA2,0);  //继续一个一个偏移
                          read(fp,&data32,sizeof (data32));  //读取内容
                         ++j;

                     }
                   sprintf(buffer,"fuction_total: %u\n",j);
                   str = QString(buffer);
                   ui->textEdit->append(str);






              }else if(identify == 64){
                  read(fp,&data64,sizeof (data64));  //读取内容至data64
                  WORD Hint = 0;  //
                  char Name3[100]{'\0'};
                  unsigned j = 0;
                  while((data64.u1.AddressOfData) != 0)  //判断是否为空
                  {
                      t = data64.u1.AddressOfData >> 63;  //因为是64位  所以 左移63位取最高位
                      number = data64.u1.AddressOfData & 0x7FFFFFFFFFFFFFFF;  //取低63位的数据作为函数的序号（如果不是以名字输出的话）

                      if(t == 1 ){
                          sprintf(buffer,"%s   %08X  ",name,number);
                          str = QString(buffer);
                          ui->textEdit->append(str);
                      }else if(t == 0)
                      {
                          FOA3 = Gets_FOA(data64.u1.AddressOfData);  //获取内容
                           _lseek(fp,FOA3,0);
                           _read(fp,&Hint,sizeof (Hint)); //移动获取输入表函数的序号
                           _read(fp,Name3,sizeof (Name3));   //取出名字
                           sprintf(buffer,"%s   %04X   %s  ",name,Hint,Name3);
                           str = QString(buffer);
                           ui->textEdit->append(str);

                      }
                      ++j;
                      FOA2 = FOA2+sizeof (data64);
                       _lseek(fp,FOA2,0);  //继续偏移  一个个输出
                        read(fp,&data64,sizeof (data64));  //读取内容
                    }
                   sprintf(buffer,"fuction_total: %u\n",j);
                   str = QString(buffer);
                   ui->textEdit->append(str);


              }
              FOA = FOA+sizeof (import_descriptor);  //FOA指向下一个
              _lseek(fp,FOA,0); //偏移指定距离
              _read(fp,&import_descriptor,sizeof (import_descriptor));//从指定的偏移位置读取书数据
            }
        }else{
            Dialog2 * c = new Dialog2();
            c->setWindowTitle("错误");
            c->exec();
        }
    }else
    {
        Dialog3  *dialog3 = new Dialog3();
        dialog3->setWindowTitle("错误");
        dialog3->exec();
    }
}
