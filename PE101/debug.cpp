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

void debug_show(Ui::PE_Widget * ui,int fp){
    if(k == 1 && fp != -1){
        _IMAGE_DEBUG_DIRECTORY debug_directory;
        int RVA= 0,FOA= 0;
        RVA = Gets_RVA(fp,6);
        FOA = Gets_FOA(RVA);
        if(FOA != -1){

            _lseek(fp,FOA,0);
            _read(fp,&debug_directory,sizeof (debug_directory));
            char buffer[60];
            ui->textEdit->append("-------debug-----");
            /*DEbug主版本*/
            sprintf(buffer,"MajorVersion: %x",debug_directory.MajorVersion);
            QString str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"MinorVersion: %x",debug_directory.MinorVersion);
            str = QString(buffer);
            ui->textEdit->append(str);

            /*DEBUG信息建立的时间*/
            sprintf(buffer,"TimeDateStamp: %lx",debug_directory.TimeDateStamp);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"Characteristics: %lx",debug_directory.Characteristics);
            str = QString(buffer);
            ui->textEdit->append(str);
            /* DEBUG数据的文件偏移*/
            sprintf(buffer,"PointerToRawData: %lx",debug_directory.PointerToRawData);
            str = QString(buffer);
            ui->textEdit->append(str);

            /*当被映射到虚拟内存时的数据大小*/
            sprintf(buffer,"AddressOfRawData: %lx",debug_directory.AddressOfRawData);
            str = QString(buffer);
            ui->textEdit->append(str);


           /*debug数据的大小*/
            sprintf(buffer,"SizeOfData: %lx",debug_directory.SizeOfData);
            str = QString(buffer);
            ui->textEdit->append(str);

            /*debug信息的类型*/
            sprintf(buffer,"Type: %lx",debug_directory.Type);
            str = QString(buffer);
            ui->textEdit->append(str);

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
