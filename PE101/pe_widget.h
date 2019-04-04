#ifndef PE_WIDGET_H
#define PE_WIDGET_H

#include <QMainWindow>
#include<dialog.h>
namespace Ui {
class PE_Widget;
}

class PE_Widget : public QMainWindow
{
    Q_OBJECT


public:

    explicit PE_Widget(QWidget *parent = nullptr);
    ~PE_Widget();

private slots:
    void on_pushButton_clicked();

    void on_pushButton_4_clicked();



    void on_pushButton_5_clicked();

    void on_pushButton_6_clicked();

    void on_pushButton_7_clicked();

    void on_pushButton_13_clicked();

    void on_pushButton_8_clicked();

    void on_pushButton_9_clicked();

    void on_pushButton_10_clicked();

    void on_pushButton_11_clicked();

    void on_pushButton_12_clicked();

private:
    Ui::PE_Widget *ui;


};

#endif // PE_WIDGET_H
