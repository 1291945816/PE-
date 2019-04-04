#include "pe_widget.h"
#include "ui_pe_widget.h"
#include"header.h"
#include"dialog.h"
#include"dialog1.h"
#include"dialog3.h"
#include<stdio.h>
#include<stdlib.h>
#include <QFileDialog>
#include<iostream>
#include<fstream>


//void PE_Widget::file_header_show(Ui::PE_Widget* ui,int fp);
void file_header_show(Ui::PE_Widget * ui,int fp);    //用于输出文件头的结构内容
void optionalheader(Ui::PE_Widget * ui,int fp);  //用于输出可选头的结构内容
void export_show(Ui::PE_Widget * ui,int fp);  //用于输出输入表的内容
void import_show(Ui::PE_Widget * ui,int fp); //用于输出输出表的内容
void resource_show(Ui::PE_Widget * ui,int fp);   //用于输出资源目录的内容
void debug_show(Ui::PE_Widget * ui,int fp);  //用于输出调试信息的内容
void tls_show(Ui::PE_Widget * ui,int fp);   //用于输出tls的内容
void base_show(Ui::PE_Widget * ui,int fp);  //用于输出重定向的内容
void _show(Ui::PE_Widget * ui, int fp); //用于输出区块表的内容



long int PEfileoffset; //PE头文件的偏移地址
long int OPfileoffset;  //可选头的偏移地址
long int SETctionoff; //区块的偏移地址
IMAGE_SECTION_HEADER section_header1[100];     //用于存放各区块 以便单独对区块的分析
int i;  //这是区块的数量
int fp;  //文件的句柄
int k = 0;  //是否按下了“选择文件”的标识
int identify = 0;  //用于临时判别数据文件是多少位

void Offcalculation(int fp);  //偏移计算  用于大的头文件

PE_Widget::PE_Widget(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::PE_Widget)
{
    ui->setupUi(this);
}

PE_Widget::~PE_Widget()
{
    delete ui;
}

void PE_Widget::on_pushButton_clicked()
{
    //该按键用于判断文件的输入是否正确以及文件是否为PE文件且计算偏移地址
    const  char *  filename;
    k = 1;
    //以下是为了获取文件的路径
    /**
     * 首先从打开的窗口获取了前往南京的路径 然后进行输出到linetext上便于用户的阅读
     * 其次 将读取的路径转化位char*型（能力有限 不能含中文）
     */
    QString file_name = QFileDialog::getOpenFileName();
    ui->lineEdit->setText(file_name.toUtf8());
   QByteArray str = file_name.toUtf8();
    filename= str.data();
     fp = open( filename,_O_BINARY|_O_RDONLY); //读取文件


    //下面就是判断是不是PE文件
    IMAGE_DOS_HEADER dos_header1;     //这是一个dos头
    IMAGE_NT_HEADERS nt_headers;  //这是一个Nt头
    /*分32位和64位*/
    IMAGE_OPTIONAL_HEADER32 optionalheader;
    IMAGE_OPTIONAL_HEADER64 optionalheader64;

    IMAGE_FILE_HEADER fileheader; //PE 文件头


    lseek(fp,0,0);
    read(fp,&dos_header1, sizeof(dos_header1));   //获取dosheader

    lseek(fp,dos_header1.e_lfanew,0);
      _read(fp,&nt_headers, sizeof(nt_headers));  //按DOS头中的Nt头真正的偏移地址找到NT头 用于判断
    lseek(fp, 0, SEEK_END); //将文件移动到尾部
    ui->lineEdit_5->clear(); //清除原有数据
    ui->lineEdit_6->clear();

    //输出文件的大小在linetext中 供用户了解
    ui->lineEdit_6->setText(QString::number((tell(fp)/1024.0)));

     if(fp == -1)  //判断文件是否打开
     {
         Dialog * c = new Dialog();
         c->setWindowTitle("错误");  //如果不能打开就弹出一个对话框
         c->exec();
     }else if(dos_header1.e_magic != IMAGE_DOS_SIGNATURE)  //判断  是否是标准的“MZ”
      {
          Dialog1 *c = new Dialog1();//定义为指针才能够避免界面闪退
          c ->setWindowTitle("错误");  //窗口标题
          c->exec();//这是一个模式  保证了该对话框没有结束 主界面不能够操作

      }else if(nt_headers.Signature != IMAGE_NT_SIGNATURE)  //用来判断NT头与PE文件的NT头的signature是否一致
      {
          Dialog1 *c = new Dialog1();
          c ->setWindowTitle("错误");  //窗口标题
          c->exec();//这是一个模式  保证了该对话框没有结束 主界面不能够操作
     }else
     {
         if(nt_headers.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)  //判断是否位32位文件
         {
             identify = 32;
             ui->lineEdit_5->setText("32");  //是就输出32
             //判断该文件是否是64位文件
         }else if(nt_headers.FileHeader.Machine == IMAGE_FILE_MACHINE_IA64 ||
                  nt_headers.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64){

            identify = 64;
            ui->lineEdit_5->setText("64"); //是就输出64
         }
         char buffer[256];  //用于存储数据 将转化的数据暂时存放到数组中 以便打印到窗口
         Offcalculation( fp); //计算偏移距离
         lseek(fp,0,0);
        read(fp,&dos_header1, sizeof(dos_header1));
        //清除原有数据
         ui->textEdit->clear();
         ui->textEdit_1->clear();
         ui->textEdit_2->setText(QString::number(dos_header1.e_magic,16));  //以16进制输出标识的数据
        _lseek(fp,PEfileoffset,0);
         _read(fp,&fileheader,sizeof (fileheader));
          ui->lineEdit_4->setText(QString::number(fileheader.NumberOfSections,16));//输出区块的数量
          //将32位和64位区别分析
         if( identify == 32)
         {
             _lseek(fp,OPfileoffset,0);//从开头偏移到可选头的位置
             _read(fp,&optionalheader,sizeof (optionalheader));
            //ui->lineEdit_4->setText(QString::number(fileheader.NumberOfSections,16));//输出区块的数量

            /*32*/
            ui->lineEdit_2->setText(QString::number(optionalheader.AddressOfEntryPoint,16));  //程序入口RVA

            sprintf(buffer,"链接程序的主版本号:%u",optionalheader.MajorLinkerVersion);
            QString str = QString(buffer);
            ui->textEdit_1->append(str);  //输出链接程序的主版本号

            sprintf(buffer,"链接程序的次版本号:%u",optionalheader.MinorLinkerVersion);
            str = QString(buffer);
            ui->textEdit_1->append(str);//输出连接程序的副版本号

            sprintf(buffer,"操作系统的最低的主版本号: %u",optionalheader.MajorOperatingSystemVersion);//要求操作系统的最低的主版本号
            str = QString(buffer);
            ui->textEdit_1->append(str);

            sprintf(buffer,"操作系统的最低的副版本号: %u",optionalheader.MinorOperatingSystemVersion);//要求操作系统的最低的副版本号
            str = QString(buffer);
            ui->textEdit_1->append(str);

            sprintf(buffer,"该执行文件的主版号:  %u",optionalheader.MajorImageVersion);  //该执行文件的主版号（依据程序员定义）
            str = QString(buffer);
            ui->textEdit_1->append(str);

            sprintf(buffer,"该执行文件的次版本号: %u",optionalheader.MinorImageVersion );//该执行文件的次版本号(依据程序员定义)
            str = QString(buffer);
            ui->textEdit_1->append(str);

            sprintf(buffer,"最低子系统的主版本号: %u",optionalheader.MajorSubsystemVersion);//要求最低子系统的主版本号
            str = QString(buffer);
            ui->textEdit_1->append(str);

            sprintf(buffer,"最低子系统的次版本号:  %u",optionalheader.MinorSubsystemVersion);//要求最低子系统的次版本号
            str = QString(buffer);
            ui->textEdit_1->append(str);
            ui->lineEdit_3->setText(QString::number(optionalheader.ImageBase,16));  //输出文件首选装入地址

         }else if(identify == 64)
         {
             _lseek(fp,OPfileoffset,0);//从开头偏移到可选头的位置
             _read(fp,&optionalheader64,sizeof (optionalheader64));


            ui->lineEdit_2->setText(QString::number(optionalheader64.AddressOfEntryPoint,16));  //程序入口RVA

            sprintf(buffer,"链接程序的主版本号:%u",optionalheader64.MajorLinkerVersion);
            QString str = QString(buffer);
            ui->textEdit_1->append(str);  //输出链接程序的主版本号

            sprintf(buffer,"链接程序的次版本号:%u",optionalheader64.MinorLinkerVersion);
            str = QString(buffer);
            ui->textEdit_1->append(str);//输出连接程序的副版本号

            sprintf(buffer,"操作系统的最低的主版本号: %u",optionalheader64.MajorOperatingSystemVersion);//要求操作系统的最低的主版本号
            str = QString(buffer);
            ui->textEdit_1->append(str);

            sprintf(&buffer[3],"操作系统的最低的副版本号: %u",optionalheader64.MinorOperatingSystemVersion);//要求操作系统的最低的副版本号
            str = QString(&buffer[3]);
            ui->textEdit_1->append(str);

            sprintf(buffer,"该执行文件的主版号:  %u",optionalheader64.MajorImageVersion);  //该执行文件的主版号（依据程序员定义）
            str = QString(buffer);
            ui->textEdit_1->append(str);

            sprintf(buffer,"该执行文件的次版本号: %u",optionalheader64.MinorImageVersion );//该执行文件的次版本号(依据程序员定义)
            str = QString(buffer);
            ui->textEdit_1->append(str);

            sprintf(buffer,"最低子系统的主版本号: %u",optionalheader64.MajorSubsystemVersion);//要求最低子系统的主版本号
            str = QString(buffer);
            ui->textEdit_1->append(str);

            sprintf(buffer,"最低子系统的次版本号:  %u",optionalheader64.MinorSubsystemVersion);//要求最低子系统的次版本号
            str = QString(buffer);
            ui->textEdit_1->append(str);
            ui->lineEdit_3->setText(QString::number(optionalheader64.ImageBase,16));  //输出文件首选装入地址




         }










     }
}


void Offcalculation(int fp){
    IMAGE_DOS_HEADER dos_header; //定义一个dos头的对象 用来获取偏移地址
    IMAGE_FILE_HEADER fileHeader; // 用于获取区块的数量


    _lseek(fp,0,0);  //fp为文件的指定符  通过移动  保证是在开头
    _read(fp,&dos_header, sizeof(dos_header));
    PEfileoffset = dos_header.e_lfanew + 0x04; //dos_header.e_lfanew  所指向的是NT结构的内容  再偏移4h才是PE文件头
    OPfileoffset= dos_header.e_lfanew + 0x18; //偏移十六进制的18是可选头部分
    if( identify == 32)//因为块表紧跟在Op头后面的
    {
         SETctionoff = OPfileoffset + sizeof(IMAGE_OPTIONAL_HEADER32);
     }else if (identify == 64)
    {
        SETctionoff = OPfileoffset + sizeof(IMAGE_OPTIONAL_HEADER64);
     }


    _lseek(fp,PEfileoffset,0);  //移动到文件头的开头
    _read(fp,&fileHeader, sizeof(fileHeader));   //读取文件头的数据


    _lseek(fp,SETctionoff,0);  //移动到区块的开头

    i = fileHeader.NumberOfSections;  //确定块的数量
    int j = 0;
    while(j != i)
    {
        _read(fp,&section_header1[j], sizeof(IMAGE_SECTION_HEADER));  //将setction的内容传到数组里面去  以便RVA->FOA
        ++j;

    }
};

/*dosheader*/
void PE_Widget::on_pushButton_4_clicked()
{
    if(k == 1 &&fp != -1 ){

        char  buffer[256];
        IMAGE_DOS_HEADER  dos_header;
        _lseek(fp,0,0); //dos头处于开头
        _read(fp,&dos_header,sizeof (dos_header));

        ui->textEdit->append("-------------------DOS_HEADER----------------------");

        sprintf(buffer,"Magic numbert: %0X",dos_header.e_magic);
        QString str = QString(QLatin1String(buffer));
        ui->textEdit->append(str);

        sprintf(buffer,"Bytes on last pages of file: %x",dos_header.e_cblp);
        str = QString(QLatin1String(buffer));
        ui->textEdit->append(str);

        sprintf(buffer,"pages in file : %0x",dos_header.e_cp);
        str = QString(QLatin1String(buffer));
        ui->textEdit->append(str);

        sprintf(buffer,"Relacation: %0x",dos_header.e_crlc);
        str = QString(QLatin1String(buffer));
        ui->textEdit->append(str);

        sprintf(buffer,"Size of header in paragraphs: %0x",dos_header.e_cparhdr);
        str = QString(QLatin1String(buffer));
        ui->textEdit->append(str);

        sprintf(buffer,"Minimum extra paragraphs needed: %0x ",dos_header.e_minalloc);
        str = QString(QLatin1String(buffer));
        ui->textEdit->append(str);

        sprintf(buffer,"Maximum extra paragraphs needed: %0x",dos_header.e_maxalloc);
        str = QString(QLatin1String(buffer));
        ui->textEdit->append(str);

        sprintf(buffer,"Ininial(ralative) SS value: %0x ",dos_header.e_ss);
        str = QString(QLatin1String(buffer));
        ui->textEdit->append(str);

        sprintf(buffer,"Ininial(relative) Sp value: %0x ",dos_header.e_sp);
        str = QString(QLatin1String(buffer));
        ui->textEdit->append(str);

       sprintf(buffer,"Checksum:  %0x ",dos_header.e_csum);
       str = QString(QLatin1String(buffer));
       ui->textEdit->append(str);

      sprintf(buffer,"Initial IP value:  %0x",dos_header.e_ip );
      str = QString(QLatin1String(buffer));
      ui->textEdit->append(str);

      sprintf(buffer,"Ininial(ralative) CS value: %0x ",dos_header.e_cs);
      str = QString(QLatin1String(buffer));
      ui->textEdit->append(str);

      sprintf(buffer,"File address of relocation table:  %0x", dos_header.e_lfarlc);
      str = QString(QLatin1String(buffer));
      ui->textEdit->append(str);

      sprintf(buffer,"Overlay number : %0x",dos_header.e_ovno);
      str = QString(QLatin1String(buffer));
      ui->textEdit->append(str);

      sprintf(buffer,"OEM identifier(for e_oeminfo):  %x",dos_header.e_oemid);
      str = QString(QLatin1String(buffer));
      ui->textEdit->append(str);

      sprintf(buffer,"OEM information;e_oemid spmid specific:  %x ",dos_header.e_oeminfo);
      str = QString(QLatin1String(buffer));
      ui->textEdit->append(str);


      sprintf(buffer,"File address of new exe header:  %lx",dos_header.e_lfanew);
      str = QString(QLatin1String(buffer));
      ui->textEdit->append(str);

      ui->textEdit->append("---------------------------end------------------");
      ui->textEdit->append("                                                          ");
        }else{
            Dialog3 * c = new Dialog3();
            c->setWindowTitle("错误");
            c->exec();

        }


}

/*fileheader*/
void PE_Widget::on_pushButton_5_clicked()
{
    file_header_show( ui, fp);

}
/*optionalheader*/
void PE_Widget::on_pushButton_6_clicked()
{
    optionalheader(ui, fp);

}
/*sectionheader*/
void PE_Widget::on_pushButton_7_clicked()
{
    _show(ui,fp);
}
/*export*/
void PE_Widget::on_pushButton_13_clicked()
{
   export_show(ui,fp);
}
/*import*/
void PE_Widget::on_pushButton_8_clicked()
{
   import_show( ui, fp);

}
/*resource*/
void PE_Widget::on_pushButton_9_clicked()
{
  resource_show( ui, fp);

}
/*debug*/
void PE_Widget::on_pushButton_10_clicked()
{
    debug_show( ui, fp);
}
/*base*/
void PE_Widget::on_pushButton_11_clicked()
{
     base_show( ui,fp);

}

/*tls*/
void PE_Widget::on_pushButton_12_clicked()
{
   tls_show( ui, fp);

}
