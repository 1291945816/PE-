#include "pe_widget.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    PE_Widget w;
    w.setWindowTitle("PE文件分析器");
    w.show();
    return a.exec();
}
