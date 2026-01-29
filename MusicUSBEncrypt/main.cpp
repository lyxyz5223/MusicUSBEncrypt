#include "MusicUSBEncrypt.h"
#include <QtWidgets/QApplication>
#include <Logger.h>
#include <vector>
#include <string>

int main(int argc, char *argv[])
{
    system("chcp 65001 > nul"); // 设置控制台为 UTF-8 编码
    std::vector<std::string> arguments;
    for (int i = 0; i < argc; ++i)
        arguments.emplace_back(argv[i]);
    if (arguments.size() > 2 && arguments[1] == "-level")
    {
        if (arguments[2] == "trace")
            Logger("main").setGlobalLevel(LogLevel::trace);
        else if (arguments[2] == "debug")
            Logger("main").setGlobalLevel(LogLevel::debug);
        else if (arguments[2] == "info")
            Logger("main").setGlobalLevel(LogLevel::info);
        else if (arguments[2] == "warning")
            Logger("main").setGlobalLevel(LogLevel::warning);
        else if (arguments[2] == "error")
            Logger("main").setGlobalLevel(LogLevel::error);
        else if (arguments[2] == "critical")
            Logger("main").setGlobalLevel(LogLevel::critical);
        else if (arguments[2] == "off")
            Logger("main").setGlobalLevel(LogLevel::off);
    }
    QApplication app(argc, argv);
    MusicUSBEncrypt window;
    window.show();
    return app.exec();
}
