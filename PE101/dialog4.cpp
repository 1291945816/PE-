#include "dialog4.h"
#include "ui_dialog4.h"

Dialog4::Dialog4(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog4)
{
    ui->setupUi(this);
}

Dialog4::~Dialog4()
{
    delete ui;
}
