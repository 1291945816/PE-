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
void base_show(Ui::PE_Widget * ui,int fp)
{
    if(k == 1 && fp != -1 )
    {
        _IMAGE_BASE_RELOCATION base_relocation;
        char buffer[60];
        int RVA = 0,FOA = 0;
        RVA = Gets_RVA(fp,5);
        FOA = Gets_FOA(RVA);
        WORD typeoffest = 0;
        unsigned type_RVA,type;
        if(FOA != -1){

            _lseek(fp,FOA,0);

            _read(fp,&base_relocation,sizeof (base_relocation));
             ui->textEdit->append("--------base------");
            while(base_relocation.VirtualAddress != 0)  //判断该块是否已经结束
            {
                   unsigned  i = 0;
                   unsigned items = (base_relocation.SizeOfBlock-8)/2;
                   sprintf(buffer,"base_items：%d",items);
                   QString str= QString(buffer);
                   ui->textEdit->append(str);

                   /*重定位块的长度（以便于后续的偏移计算）*/
                   sprintf(buffer,"SizeOfBlock:%08lX",base_relocation.SizeOfBlock);
                   str= QString(buffer);
                   ui->textEdit->append(str);

                     /*重定位数据开始的*/
                    sprintf(buffer,"VirtualAddress: %08lX",base_relocation.VirtualAddress);
                    str= QString(buffer);
                    ui->textEdit->append(str);
                    while(i < items) //读取紧跟其后的typeoffest
                    {
                        _read(fp,&typeoffest,sizeof (typeoffest));
                        //取最高位

                        type = typeoffest >> 12;//左移12位 也就是取最高4位的数据

                        //取低12位数据做RVA的一部分 也就是  与  0000 1111 1111 1111 -> 0x0FFF
                        type_RVA = (typeoffest & 0x0FFF) + base_relocation.VirtualAddress;
                        if(type == 0) //最高4位是属性  如果是0 则为...ABSOLUTE(无具体含义 仅仅是为了每段4个字节对齐)
                        {
                            sprintf(buffer,"item: %08lX  RVA : %08X  type: ABSOLUTE",typeoffest,type_RVA);
                            str= QString(buffer);
                            ui->textEdit->append(str);
                        }else if(type == 3)//如果是3 则是 ...HIGHLOW(出现在32中)  重定位所指向的地址都要被修正
                        {
                            sprintf(buffer,"item: %08lX  RVA : %08X  type:HIGHLOW ",typeoffest,type_RVA);
                            str= QString(buffer);
                            ui->textEdit->append(str);
                        }else if(type ==10)  //如果是 10  则是...DIR64(出现在64位中)  也是所指向的整个地址 都要被修正
                        {
                            sprintf(buffer,"item: %08lX  RVA : %08X  type: DIR64",typeoffest,type_RVA);
                            str= QString(buffer);
                            ui->textEdit->append(str);
                        }
                        ++i;
                    }
                     ui->textEdit->append("\n");
                    FOA = FOA+base_relocation.SizeOfBlock; //将该重定位块的数据大小与原来的偏移地址加起来便是下一个重定位块的的起始地址

                     _lseek(fp,FOA,0); //继续偏移
                     _read(fp,&base_relocation,sizeof (base_relocation));  // 继续读取数据
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
