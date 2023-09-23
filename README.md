# PwnPatcher

一个快速修补漏洞的pwn工具，支持x86、x64、mips、mips64、arm、aarch64架构；提供了通过修改eh_frame、在程序中直接patch、快速patch格式化字符串漏洞、向eh_frame中写入常量字符串等功能，目前仅支持linux下的ELF文件的修补

## 安装

安装依赖：

```bash
pip install pwntools pyqt5 pyqt5-tools keystone-engine -i https://pypi.tuna.tsinghua.edu.cn/simple
```

下载PwnPatcher文件
```bash
git clone https://github.com/D1ag0n-Young/PwnPatcher.git
```

将PwnPatcher.py拷贝到`%IDAPATH%/plugins/` 目录下，重启ida即可

## 使用

启动快捷键`ALT-K`,以下是插件的具体功能：

1. Patch address range (hex)  patch范围，分为当前起始地址和自定义结束地址
2. patch constant in          选择patch常量字符到eh_frame还是指定的start_addr处
3. constant                   需要向eh_frame段写入的字符串
4. constant_address           写入的字符串地址，默认为None，即尚未写入
5. Assembly code              输入需要patch的汇编代码，多行以`\n`或`;`分隔
6. Encode code                输入的汇编代码对应的机器码，显示字节数，异常汇编显示`...`
7. patch constant             写入常量字符串的触发按钮，写入成功会相应刷新constant_address的值
8. Patch by jmp               通过在当前位置写入jmp eh_frame_addr,在eh_frame处添加patch逻辑，修改eh_frame权限，再跳回指定的结束地址处
9. Patch by original          当前位置进行patch
10. Patch fmt by call         仅支持x86/64，在当前位置调用call eh_frame_addr实现修补
11. patcher log               在ida的OutPut窗口查看patch记录
12. init patcher              初始化PwnPatcher为初始值

patch过程存在于内存，ida并不能直接看到，patch成功后的文件存放于当前目录，命令方式为`[name]_patch`,以`_patch`结尾

## todo

目前插件依赖三方库较多，后续考虑使用原生idaapi进行实现，预期效果：

1. patch过程可以直接在ida界面展示
2. 支持exe等其他架构和语言的patch
