#include "pe_widget.h"
#include "ui_pe_widget.h"
#include"header.h"
#include"dialog.h"
#include"dialog1.h"
#include"dialog3.h"
#include<stdio.h>
#include<stdlib.h>

extern long int OPfileoffset;  //可选头的偏移地址
extern int k;
extern int  identify;

void optionalheader(Ui::PE_Widget * ui,int fp)
{
      char buffer[256];
    if(k == 1 && fp != -1){
        if(identify == 32){
            IMAGE_OPTIONAL_HEADER32 option_Header;



             _lseek(fp,OPfileoffset,0);//从0开始偏移到可选头的初位置
             _read(fp,&option_Header,sizeof (option_Header));

            ui->textEdit->append("-----------OPTIONALHEADER---------------");

            sprintf(buffer,"Magic: %x",option_Header.Magic); //是一个标识字  用来说明文件是ROM映像（0107h）还是 普通映像文件（010Bh）
            QString str= QString(QLatin1String(buffer));
             ui->textEdit->append(str);

             sprintf(buffer,"SizeOfCode : %lx",option_Header.SizeOfCode);  //所有带有IMAGE—SCN_CODE属性的区块大小
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"SizeOfInitializedData:  %lx",option_Header.SizeOfInitializedData );//已初始化的数据块大小（一般这数据是不准确的）
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"SizeOfUninitializedData :  %lx",option_Header.SizeOfUninitializedData);//未初始化的的数据块大小
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"BaseOfCode: %lx",option_Header.BaseOfCode);//代码段的RVA
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

             sprintf(buffer,"BaseOfData:  %lx",option_Header.BaseOfData);//数据段的RVA
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"SectionAlignment: %lx",option_Header.SectionAlignment);//装入内存时候的文件区块对齐大小
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"FileAlignment: %lx",option_Header.FileAlignment); //磁盘上PE文件的区块对齐大小
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"Win32VersionValue:  %lx",option_Header.Win32VersionValue);//一个从来不用的字段  是0
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"SizeOfImage: %lx",option_Header.SizeOfImage);//映像装入内存后的尺寸大小
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(&buffer[10],"SizeOfHeaders: %lx",option_Header.SizeOfHeaders );//DOs头  PE头  区块表的组合尺寸
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"CheckSum : %lx",option_Header.CheckSum); //映像的文件校验和
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

             sprintf(buffer,"Subsystem: %x",option_Header.Subsystem);//一个可标明执行文件所期望的子系统的枚举值
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"DllCharacteristics:  %x ",option_Header.DllCharacteristics);//这个DLLmain()函数何时被调用
            str = QString(QLatin1String(buffer));
             ui->textEdit->append(str);

            sprintf(&buffer[14],"SizeOfStackReserve:  %lx",option_Header.SizeOfStackReserve);//exe文件里 为堆栈保留的大小
             str = QString(QLatin1String(buffer));
             ui->textEdit->append(str);

            sprintf(buffer,"SizeOfStackCommit: %lx",option_Header.SizeOfStackCommit);//exe文件里 一开始就被委派给堆栈的内存数量 默认4k
             str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"SizeOfHeapReserve : %lx",option_Header.SizeOfHeapReserve);//exe文件  为进程默认保留的堆大小 默认1MB
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"SizeOfHeapCommit:  %lx ",option_Header.SizeOfHeapCommit);//exe文件里委派给堆的内存大小
            str = QString(QLatin1String(buffer));
            ui->textEdit->append(str);

            sprintf(buffer,"LoaderFlags: %lx",option_Header.LoaderFlags);//与调试有关  默认为0
            str = QString(QLatin1String(buffer));
           ui->textEdit->append(str);

           sprintf(buffer,"NumberOfRvaAndSizes :  %lx",option_Header.NumberOfRvaAndSizes);//数据目录的项数
           str = QString(QLatin1String(buffer));
           ui->textEdit->append(str);

            //数据目录表的内容（RVA和size）
            /*输出表*/
             sprintf(buffer,"(输出表)VirtualAddress: %lx   size: %lx",option_Header.DataDirectory[0].VirtualAddress,option_Header.DataDirectory[0].Size);
             str = QString(buffer);
             ui->textEdit->append(str);

            /*输入表*/
           sprintf(buffer,"(输入表)VirtualAddress: %lx   size: %lx",option_Header.DataDirectory[1].VirtualAddress,option_Header.DataDirectory[1].Size);
            str = QString(buffer);
          ui->textEdit->append(str);

            /*资源表*/
           sprintf(buffer,"(资源)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[2].VirtualAddress,option_Header.DataDirectory[2].Size);
           str = QString(buffer);
           ui->textEdit->append(str);


             /*异常表*/
            sprintf(buffer,"(异常)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[3].VirtualAddress,option_Header.DataDirectory[3].Size);
            str = QString(buffer);
            ui->textEdit->append(str);


              /*安全表*/
             sprintf(buffer,"(安全)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[4].VirtualAddress,option_Header.DataDirectory[4].Size);
             str = QString(buffer);
             ui->textEdit->append(str);



            sprintf(buffer,"(重定位表)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[5].VirtualAddress,option_Header.DataDirectory[5].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

               sprintf(buffer,"(调试信息)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[6].VirtualAddress,option_Header.DataDirectory[6].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"(版权信息)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[7].VirtualAddress,option_Header.DataDirectory[7].Size);
            str = QString(buffer);
             ui->textEdit->append(str);

            sprintf(buffer,"(RVA of GP)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[8].VirtualAddress,option_Header.DataDirectory[8].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

             sprintf(buffer,"(TLS Diretory)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[9].VirtualAddress,option_Header.DataDirectory[9].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"(load Configuration )VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[10].VirtualAddress,option_Header.DataDirectory[10].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"(Bound import)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[11].VirtualAddress,option_Header.DataDirectory[11].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"(导入函数地址表)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[12].VirtualAddress,option_Header.DataDirectory[12].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"(Delay ...)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[13].VirtualAddress,option_Header.DataDirectory[13].Size);
             str = QString(buffer);
            ui->textEdit->append(str);


            sprintf(buffer,"(COM ...)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[14].VirtualAddress,option_Header.DataDirectory[14].Size);
            str = QString(buffer);
            ui->textEdit->append(str);
        }else if(identify == 64){
            IMAGE_OPTIONAL_HEADER64 option_Header;



             _lseek(fp,OPfileoffset,0);//从0开始偏移到可选头的初位置
             _read(fp,&option_Header,sizeof (option_Header));

            ui->textEdit->append("-----------OPTIONALHEADER---------------");

            sprintf(&buffer[0],"Magic: %x",option_Header.Magic); //是一个标识字  用来说明文件是ROM映像（0107h）还是 普通映像文件（010Bh）
            QString str= QString(QLatin1String(&buffer[0]));
             ui->textEdit->append(str);

             sprintf(&buffer[1],"SizeOfCode : %lx",option_Header.SizeOfCode);  //所有带有IMAGE—SCN_CODE属性的区块大小
            str = QString(QLatin1String(&buffer[1]));
            ui->textEdit->append(str);

            sprintf(&buffer[2],"SizeOfInitializedData:  %lx",option_Header.SizeOfInitializedData );//已初始化的数据块大小（一般这数据是不准确的）
            str = QString(QLatin1String(&buffer[2]));
            ui->textEdit->append(str);

            sprintf(&buffer[3],"SizeOfUninitializedData :  %lx",option_Header.SizeOfUninitializedData);//未初始化的的数据块大小
            str = QString(QLatin1String(&buffer[3]));
            ui->textEdit->append(str);

            sprintf(&buffer[4],"BaseOfCode: %lx",option_Header.BaseOfCode);//代码段的RVA
            str = QString(QLatin1String(&buffer[4]));
            ui->textEdit->append(str);

            sprintf(&buffer[6],"SectionAlignment: %lx",option_Header.SectionAlignment);//装入内存时候的文件区块对齐大小
            str = QString(QLatin1String(&buffer[6]));
            ui->textEdit->append(str);

            sprintf(&buffer[7],"FileAlignment: %lx",option_Header.FileAlignment); //磁盘上PE文件的区块对齐大小
            str = QString(QLatin1String(&buffer[7]));
            ui->textEdit->append(str);

            sprintf(&buffer[8],"Win32VersionValue:  %lx",option_Header.Win32VersionValue);//一个从来不用的字段  是0
            str = QString(QLatin1String(&buffer[8]));
            ui->textEdit->append(str);

            sprintf(&buffer[9],"SizeOfImage: %lx",option_Header.SizeOfImage);//映像装入内存后的尺寸大小
            str = QString(QLatin1String(&buffer[9]));
            ui->textEdit->append(str);

            sprintf(&buffer[10],"SizeOfHeaders: %lx",option_Header.SizeOfHeaders );//DOs头  PE头  区块表的组合尺寸
            str = QString(QLatin1String(&buffer[10]));
            ui->textEdit->append(str);

            sprintf(&buffer[11],"CheckSum : %lx",option_Header.CheckSum); //映像的文件校验和
            str = QString(QLatin1String(&buffer[11]));
            ui->textEdit->append(str);

             sprintf(&buffer[12],"Subsystem: %x",option_Header.Subsystem);//一个可标明执行文件所期望的子系统的枚举值
            str = QString(QLatin1String(&buffer[12]));
            ui->textEdit->append(str);

            sprintf(&buffer[13],"DllCharacteristics:  %x ",option_Header.DllCharacteristics);//这个DLLmain()函数何时被调用
            str = QString(QLatin1String(&buffer[13]));
             ui->textEdit->append(str);

            sprintf(&buffer[14],"SizeOfStackReserve:  %llx",option_Header.SizeOfStackReserve);//exe文件里 为堆栈保留的大小
             str = QString(QLatin1String(&buffer[14]));
             ui->textEdit->append(str);

            sprintf(&buffer[15],"SizeOfStackCommit: %llx",option_Header.SizeOfStackCommit);//exe文件里 一开始就被委派给堆栈的内存数量 默认4k
             str = QString(QLatin1String(&buffer[15]));
            ui->textEdit->append(str);

            sprintf(&buffer[16],"SizeOfHeapReserve : %llx",option_Header.SizeOfHeapReserve);//exe文件  为进程默认保留的堆大小 默认1MB
            str = QString(QLatin1String(&buffer[16]));
            ui->textEdit->append(str);

            sprintf(&buffer[17],"SizeOfHeapCommit:  %llx ",option_Header.SizeOfHeapCommit);//exe文件里委派给堆的内存大小
            str = QString(QLatin1String(&buffer[17]));
            ui->textEdit->append(str);

            sprintf(&buffer[18],"LoaderFlags: %lx",option_Header.LoaderFlags);//与调试有关  默认为0
            str = QString(QLatin1String(&buffer[18]));
           ui->textEdit->append(str);

           sprintf(&buffer[19],"NumberOfRvaAndSizes :  %lx",option_Header.NumberOfRvaAndSizes);//数据目录的项数
           str = QString(QLatin1String(&buffer[19]));
           ui->textEdit->append(str);

            //数据目录表的内容（RVA和size）
            /*输出表*/
             sprintf(buffer,"(输出表)VirtualAddress: %lx   size: %lx",option_Header.DataDirectory[0].VirtualAddress,option_Header.DataDirectory[0].Size);
             str = QString(buffer);
             ui->textEdit->append(str);

            /*输入表*/
           sprintf(buffer,"(输入表)VirtualAddress: %lx   size: %lx",option_Header.DataDirectory[1].VirtualAddress,option_Header.DataDirectory[1].Size);
            str = QString(buffer);
          ui->textEdit->append(str);

            /*资源表*/
           sprintf(buffer,"(资源)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[2].VirtualAddress,option_Header.DataDirectory[2].Size);
           str = QString(buffer);
           ui->textEdit->append(str);


             /*异常表*/
            sprintf(buffer,"(异常)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[3].VirtualAddress,option_Header.DataDirectory[3].Size);
            str = QString(buffer);
            ui->textEdit->append(str);


              /*安全表*/
             sprintf(buffer,"(安全)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[4].VirtualAddress,option_Header.DataDirectory[4].Size);
             str = QString(buffer);
             ui->textEdit->append(str);



            sprintf(buffer,"(重定位表)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[5].VirtualAddress,option_Header.DataDirectory[5].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

               sprintf(buffer,"(调试信息)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[6].VirtualAddress,option_Header.DataDirectory[6].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"(版权信息)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[7].VirtualAddress,option_Header.DataDirectory[7].Size);
            str = QString(buffer);
             ui->textEdit->append(str);

            sprintf(buffer,"(RVA of GP)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[8].VirtualAddress,option_Header.DataDirectory[8].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

             sprintf(buffer,"(TLS Diretory)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[9].VirtualAddress,option_Header.DataDirectory[9].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"(load Configuration )VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[10].VirtualAddress,option_Header.DataDirectory[10].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"(Bound import)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[11].VirtualAddress,option_Header.DataDirectory[11].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"(导入函数地址表)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[12].VirtualAddress,option_Header.DataDirectory[12].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"(Delay ...)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[13].VirtualAddress,option_Header.DataDirectory[13].Size);
             str = QString(buffer);
            ui->textEdit->append(str);


            sprintf(buffer,"(COM ...)VirtualAddress: %lx  size: %lx",option_Header.DataDirectory[14].VirtualAddress,option_Header.DataDirectory[14].Size);
            str = QString(buffer);
            ui->textEdit->append(str);

        }

    }
    else
    {
        Dialog3 * c = new Dialog3();
        c->setWindowTitle("错误");
        c->exec();
    }

}
