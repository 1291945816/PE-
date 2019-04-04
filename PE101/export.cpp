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
void export_show(Ui::PE_Widget * ui,int fp){
if(k == 1 && fp != -1)
{
    _IMAGE_EXPORT_DIRECTORY export_directory;

    //文件相对虚拟偏移  文件偏移
    int FOA = 0;
    int RVA = 0;
    int RVA_2[1000] ;//用来获取函数名的RVA

    int FOA_filename = 0;
    int FOA_2=0 ; //用来获取输出函数的RVA数组
    int FOA_3 = 0;//获取函数名的偏移地址

    DWORD FOA_4 = 0;
    WORD number = 0;

    char name[100]; //函数名
    char filename[50];

   RVA = Gets_RVA(fp,0);  //数据目录表第一个 （输出表）
    FOA = Gets_FOA(RVA);  //获取文件偏移地址

    if(FOA != -1)  //判断这个RVA是否存在
    {
        _lseek(fp,FOA,0);
        _read(fp,&export_directory,sizeof (export_directory));
        char buffer[60];
       ui->textEdit->append("--------export------");
        /*表示输出属性的旗标 一般被设置为0*/
        sprintf(buffer,"Characteristics: %lx",export_directory.Characteristics);
        QString str = QString(buffer);
        ui->textEdit->append(str);


        /*输出于函数绑定的DEll名字*/
        sprintf(buffer,"(RVA)Name:%lx ",export_directory.Name);
        str = QString(buffer);
        ui->textEdit->append(str);


        /*输出表创建时间*/
        sprintf(buffer,"TimeDateStamp: %lx",export_directory.TimeDateStamp);
        str = QString(buffer);
        ui->textEdit->append(str);


        /*一组存放RVA的数组的RVA*/
        sprintf(buffer,"(RVA)AddressOfFunctions: %lx",export_directory.AddressOfFunctions);
        str = QString(buffer);
        ui->textEdit->append(str);


        /*一个指向一组字符串RVA的RVA*/
        sprintf(buffer,"(RVA)AddressOfNames: %lx",export_directory.AddressOfNames);
        str = QString(buffer);
        ui->textEdit->append(str);


        /*输出序数表的RVA*/
        sprintf(buffer,"(RVA)AddressOfNameOrdinals: %lx",export_directory.AddressOfNameOrdinals);
        str = QString(buffer);
        ui->textEdit->append(str);



        /*这个字段包含用于这个可执行文件输出表的起始序数值*/
        sprintf(buffer,"Base : %lx",export_directory.Base);
        str = QString(buffer);
        ui->textEdit->append(str);


        /*输出表的主版本号*/
        sprintf(buffer,"MajorVersion: %lx",export_directory.MajorVersion);
        str = QString(buffer);
        ui->textEdit->append(str);


        /*输出表的次版本号*/
        sprintf(buffer,"MinorVersion: %lx",export_directory.MinorVersion);
        str = QString(buffer);
        ui->textEdit->append(str);

       /*函数的个数*/
        sprintf(buffer,"NumberOfFunctions: %lx",export_directory.NumberOfFunctions);
        str = QString(buffer);
        ui->textEdit->append(str);


        /*输出名称表的条目*/
        sprintf(buffer,"NumberOfNames: %lx\n",export_directory.NumberOfNames);
        str = QString(buffer);
        ui->textEdit->append(str);


        FOA_filename = Gets_FOA(export_directory.Name);
        _lseek(fp,FOA_filename,0);
        _read(fp,filename,sizeof (filename));

        sprintf(buffer,"Filename: %s",filename);  //输出与之关联的文件名
        str = QString(buffer);
        ui->textEdit->append(str);

        int i =0;
        FOA_2 = Gets_FOA(export_directory.AddressOfNames);

        _lseek(fp,FOA_2,0);


        for(;i <export_directory.NumberOfNames ;++i)
        {
            /*读取函数名称RVA*/
            _read(fp,&RVA_2[i],sizeof (DWORD));

        }
        i = 0;
        FOA_4 = Gets_FOA(export_directory.AddressOfNameOrdinals);
        for(;i <export_directory.NumberOfNames ;++i)
        {
            FOA_3 = Gets_FOA(RVA_2[i]);
            _lseek(fp,FOA_3,0);
            _read(fp,name,sizeof (name));
             _lseek(fp,FOA_4,0);
             FOA_4 = FOA_4+sizeof (WORD);
             _read(fp,&number,sizeof (WORD));
             sprintf(buffer,"(ORD):%04X|(NAMEORD):%04X|(函数名):%s",number,number+export_directory.Base,name);  //输出与之有关的函数
            str = QString(buffer);
            ui->textEdit->append(str);

        }
























































    }else
    {
        Dialog2 * c = new Dialog2();
        c->setWindowTitle("错误");
        c->exec();
    }
}else{
    Dialog3 * dialog3 = new Dialog3();
    dialog3->setWindowTitle("错误");
    dialog3->exec();

}









}

