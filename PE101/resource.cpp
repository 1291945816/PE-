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


int Gets_FOA(  int adress);

extern int k;  //一个标识  用来表示  是否按了开始分析的键
void resource_show(Ui::PE_Widget * ui,int fp){

    if(k == 1 && fp != -1)
    {

        _IMAGE_RESOURCE_DIRECTORY  resoure_directory;


        char buffer[256];

         int RVA = 0,FOA = 0;
        RVA  = Gets_RVA(fp,2);
        FOA = Gets_FOA(RVA);


        if(FOA != -1)
        {
            _lseek(fp,FOA,0);
            _read(fp,&resoure_directory,sizeof (resoure_directory));

            ui->textEdit->append("-----------resource-----");
            /*资源的属性标志*/

            sprintf(buffer,"Characteristics: %lx",resoure_directory.Characteristics);
            QString str = QString(buffer);
            ui->textEdit->append(str);

            /*资源建立的时间*/
            sprintf(buffer,"TimeDateStamp: %lx",resoure_directory.TimeDateStamp);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"MinorVersion: %x",resoure_directory.MinorVersion);
            str = QString(buffer);
            ui->textEdit->append(str);

            sprintf(buffer,"MajorVersion: %x",resoure_directory.MajorVersion);
            str = QString(buffer);
            ui->textEdit->append(str);

            /*使用ID数字资源条目的个数*/
            sprintf(buffer,"NumberOfIdEntries : %x",resoure_directory.NumberOfIdEntries);
            str = QString(buffer);
            ui->textEdit->append(str);


            /*使用名字的资源条目*/
            sprintf(buffer,"NumberOfNamedEntries : %x",resoure_directory.NumberOfNamedEntries);
            str = QString(buffer);
            ui->textEdit->append(str);
        }else
        {

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
