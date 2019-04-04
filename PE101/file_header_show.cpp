#include "pe_widget.h"
#include "ui_pe_widget.h"
#include"header.h"
#include"dialog.h"
#include"dialog1.h"
#include"dialog3.h"
#include<stdio.h>
#include<stdlib.h>


extern long int PEfileoffset; //PE头文件的偏移地址
extern int k;  //一个标识  用来表示  是否按了开始分析的键
void file_header_show(Ui::PE_Widget * ui,int fp)
{
    if(k == 1 && fp != -1)  //保证了  先按开始分析按钮  然后才能分析
    {
        IMAGE_FILE_HEADER  fileheader;
        _lseek(fp,PEfileoffset,0);   //根据偏移位置  找到Pe文件头的起始位置 并读取数据
        _read(fp,&fileheader, sizeof(fileheader));

        ui->textEdit->append("-----------------------FILEHEADER--------------------");

        char buffer[50];

       sprintf(buffer,"Machine:  %x",fileheader.Machine); //可执行文件的目标CPU类型
       QString str =QString(QLatin1String(buffer));//将char*转化为Qstring类型  以下的操作意思均一致
       ui->textEdit->append(str);  //输出结果到下一行  也就是紧紧接着上一行的内容

       sprintf(buffer,"TimeDateStamp:  %lx",fileheader.TimeDateStamp ); //表明文件是何时被创建的
       str = QString(QLatin1String(buffer));
       ui->textEdit->append(str);

      sprintf(buffer,"PointerToSymbolTable:  %lx",fileheader.PointerToSymbolTable);//coff表的文件偏移位置
      str = QString(QLatin1String(buffer));
      ui->textEdit->append(str);

      sprintf(buffer,"NumberOfSymbols:  %lx",fileheader.NumberOfSymbols);//符号表的符号数目 如果有符号表 这个是需要的
      str = QString(QLatin1String(buffer));
      ui->textEdit->append(str);

     sprintf(buffer,"SizeOfOptionalHeader:  %x",fileheader.SizeOfOptionalHeader);//可选头的数据大小
     str = QString(QLatin1String(buffer));
     ui->textEdit->append(str);

     sprintf(buffer,"Characteristics:  %x",fileheader.Characteristics); //文件属性  dll文件一般是 0210h  exe文件一般是 010fh
     str = QString(QLatin1String(buffer));
     ui->textEdit->append(str);


     ui->textEdit->append("-------------------------end--------------------");
     ui->textEdit->append("                                                                         ");

    }else{
        Dialog3 * c = new Dialog3();  //new 一个窗口对象用来 提醒用户
        c->setWindowTitle("错误");
        c->exec();  //区别于show  这是一个模式窗口展示  只要该窗口开着  主界面无法进行操作
    }




}

