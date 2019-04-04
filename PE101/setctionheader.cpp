#include "pe_widget.h"
#include "ui_pe_widget.h"
#include"header.h"
#include"dialog.h"
#include"dialog1.h"
#include"dialog3.h"
#include<stdio.h>
#include<stdlib.h>

extern long int SETctionoff; //区块的偏移地址
extern int k ;
extern int i; //块表的数量
extern IMAGE_SECTION_HEADER section_header1[100];     //各区块
void _show(Ui::PE_Widget * ui,int fp){
    if(k == 1 && fp != -1)
    {

        ui->textEdit->append("-----------SETCTION----");
        char buffer[256];
        int t = 0;
        while(t != i )
        {
            /*输出块名*/
            sprintf(buffer,"name:  %s",section_header1[t].Name);
            QString str = QString(buffer);
            ui->textEdit->append(str);


            /*加载到内存中的RVA*/
            sprintf(buffer,"VirtualAddress: %lx",section_header1[t].VirtualAddress);
            str = QString(buffer);
            ui->textEdit->append(str);


            /*该块在磁盘文件中的大小*/
            sprintf(buffer,"SizeOfRawData:  %lx",section_header1[t].SizeOfRawData);
            str = QString(buffer);
            ui->textEdit->append(str);

            /* 该块在磁盘文件的偏移*/
            sprintf(buffer,"PointerToRawData:  %lx",section_header1[t].PointerToRawData);
            str = QString(buffer);
            ui->textEdit->append(str);


            /*这个在exe文件中无意义 但在obj中是文件的重定位信息的偏移值*/
            sprintf(buffer,"PointerToRelocations:  %lx",section_header1[t].PointerToRelocations);
            str = QString(buffer);
            ui->textEdit->append(str);


            /*符号表在文件中的偏移值*/
            sprintf(buffer,"PointerToLinenumbers:  %lx",section_header1[t].PointerToLinenumbers);
            str = QString(buffer);
            ui->textEdit->append(str);


            /*在obj文件中 这是本块在重定位表中重定位的数目*/
            sprintf(buffer,"NumberOfRelocations:   %x",section_header1[t].NumberOfRelocations);
            str = QString(buffer);
            ui->textEdit->append(str);


            /*该块在符号表中的行号数目*/
            sprintf(buffer,"NumberOfLinenumbers:   %x",section_header1[t].NumberOfLinenumbers);
            str = QString(buffer);
            ui->textEdit->append(str);

            /*块属性*/
            sprintf(buffer,"Characteristics:  %lx",section_header1[t].Characteristics);
            str = QString(buffer);
            ui->textEdit->append(str);

            ui->textEdit->append("---------\n");

            ++t;
        }
    }else
    {
        Dialog3 * c = new Dialog3();
        c->setWindowTitle("错误");
        c->exec();
    }





}
