
## 一个简易的PE文件分析器

### 功能简介：
这是一个属于Windows 底层安全的PE文件分析器，该PE文件分析器目前实现的功能有：能够分析出基本的PE的DOS头，FILE头，OPTIONAL头的结构内容以及区块表的各个区块的内容，能够分析出导出表的基本内容（导出表的结构内容以及导出表内的输出函数和输出函数的序号），能够分析出导入表的全部内容（包括了导入表的可执行输入函数以及它的序号（顺带也标明了它是属于哪个DLL的）），基本分析出了数据目录表中所指向的资源，tls，调试的基本数据，未能进行深入，全部输出了重定位表的各重定位项的内容。同时能够在用户进行错误输入时会有相应的提醒，在不存在某方面的内容时，也会弹出小窗口进行提醒。
### 用到的技术：
主要是以C/C++ 语言，同时以Qt的ui界面为辅选择控件来构建GUI；

### 运行介绍：
直接运行该程序后会弹出一个上图界面，直接点击“选择文件”按钮，便会弹出相应打开系统内的文件的窗口，依据你所想的文件，选择文件并点击“打开”即可，此时PE文件已经处于打开状态，不必再次点击“选择文件”按钮（注意），依据所想了解的实现的功能，依次点开就可以了。
#### 注：在代码中已经进行了注释，这里便不再分析代码内容
---19/12/3补
### 界面设计

### 实际运行效果

### 目录结构
