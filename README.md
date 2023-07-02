# HZAU_ComprehensiveTraining2023_ELFParser
## 《综合实训》项目——实现一个ELF文件解析器
本项目是HZAU_CS2020级的《综合实训》项目<br>
ELFParser文件夹中的仅为源代码；other文件夹中包含学习资料和源代码+测试代码，仅供参考。<br>

已实现的ELF解析器的命令选项包括：<br>
**-h、-l、-S、-t、-s、-r、-d、-x、-I、-H**等10个。<br>
其中，几乎所有命令选项的实现效果与readelf命令近似；只有-I命令与readelf -I有较大出入，可能存在bug。<br>

注意，项目的运行环境为：<br>
**WSL2+Ubuntu20.04+gcc9.4.0** <br>
编译命令为：<br>
**gcc main.c -o main -m32**，不需要makefile <br>
经测试，本项目无warning和error，所有命令均可正常执行。<br>
