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

void tls_show(Ui::PE_Widget * ui,int fp)
{
    if(k == 1 && fp != -1)
    {

        _IMAGE_TLS_DIRECTORY32 tls_directory32;
        _IMAGE_TLS_DIRECTORY64 tls_directory64;

        int RVA = 0,FOA = 0;
        char buffer[256];

        RVA = Gets_RVA(fp,9);  //根据数据目录表获取RVA
        FOA = Gets_FOA(RVA); //转化为文件偏移地址
        if(FOA != -1)
        {
            _lseek(fp,FOA,0);
            if(identify == 32){
                _read(fp,&tls_directory32,sizeof (tls_directory32));

                ui->textEdit->append("------tls-----");
                /**/
                sprintf(buffer,"Characteristics: %lx",tls_directory32.Characteristics);
                QString str = QString(buffer);
                ui->textEdit->append(str);

                /*内存起始地址*/
                sprintf(buffer,"StartAddressOfRawData: %lx",tls_directory32.StartAddressOfRawData);
                str = QString(buffer);
                ui->textEdit->append(str);

                /*初始化的数据大小*/
                sprintf(buffer,"SizeOfZeroFill: %lx",tls_directory32.SizeOfZeroFill);
                str = QString(buffer);
                ui->textEdit->append(str);

                 /*内存的终止地址*/
                sprintf(buffer,"EndAddressOfRawData: %lx",tls_directory32.EndAddressOfRawData);
                str = QString(buffer);
                ui->textEdit->append(str);

                /*索引地址*/
                sprintf(buffer,"AddressOfIndex: %lx",tls_directory32.AddressOfIndex);
                str = QString(buffer);
                ui->textEdit->append(str);

                /*函数指针的数组的地址*/
                sprintf(buffer,"AddressOfCallBacks: %lx",tls_directory32.AddressOfCallBacks);
                str = QString(buffer);
                ui->textEdit->append(str);
            } else if(identify == 64){

                _read(fp,&tls_directory64,sizeof (tls_directory64));

                ui->textEdit->append("------tls-----");
                /**/
                sprintf(buffer,"Characteristics: %lx",tls_directory64.Characteristics);
                QString str = QString(buffer);
                ui->textEdit->append(str);

                /*内存起始地址*/
                sprintf(buffer,"StartAddressOfRawData: %lx",tls_directory64.StartAddressOfRawData);
                str = QString(buffer);
                ui->textEdit->append(str);

                /*初始化的数据大小*/
                sprintf(buffer,"SizeOfZeroFill: %lx",tls_directory64.SizeOfZeroFill);
                str = QString(buffer);
                ui->textEdit->append(str);

                 /*内存的终止地址*/
                sprintf(buffer,"EndAddressOfRawData: %lx",tls_directory64.EndAddressOfRawData);
                str = QString(buffer);
                ui->textEdit->append(str);

                /*索引地址*/
                sprintf(buffer,"AddressOfIndex: %lx",tls_directory64.AddressOfIndex);
                str = QString(buffer);
                ui->textEdit->append(str);

                /*函数指针的数组的地址*/
                sprintf(buffer,"AddressOfCallBacks: %lx",tls_directory64.AddressOfCallBacks);
                str = QString(buffer);
                ui->textEdit->append(str);
                }

        }else{
            Dialog2 * c = new Dialog2();
            c->setWindowTitle("错误");
            c->exec();

   }
    }else{
        Dialog3  *dialog3 = new Dialog3();
        dialog3->setWindowTitle("错误");
        dialog3->exec();

    }











}
