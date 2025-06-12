CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
TARGET = client
SOURCES = client.cpp

# 检测操作系统
UNAME_S := $(shell uname -s)

# 依赖库
LIBS = -lcurl

# Linux特定设置
ifeq ($(UNAME_S),Linux)
    LIBS += -lpthread
    # 静态链接选项（用于跨系统兼容性）
    STATIC_LIBS = -static-libgcc -static-libstdc++ -lcurl -lpthread
    STATIC_CXXFLAGS = $(CXXFLAGS) -static
endif

# macOS特定设置
ifeq ($(UNAME_S),Darwin)
    LIBS += -lpthread
    # 如果使用Homebrew安装的库
    CXXFLAGS += -I/opt/homebrew/include
    LDFLAGS += -L/opt/homebrew/lib
endif

# Windows特定设置 (使用MinGW)
ifeq ($(OS),Windows_NT)
    TARGET = client.exe
    LIBS += -lws2_32 -lpdh -lpsapi
    CXXFLAGS += -DWIN32_LEAN_AND_MEAN
endif

# 默认目标
all: $(TARGET)

# 编译目标（动态链接）
$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

# 静态链接目标（跨系统兼容）
static: $(SOURCES)
ifeq ($(UNAME_S),Linux)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -static-libgcc -static-libstdc++ -o $(TARGET)_static $(SOURCES) $(LIBS)
	@echo "静态链接版本已创建：$(TARGET)_static"
	@echo "这个版本在大多数Linux系统上都能运行"
else
	@echo "静态链接目前只支持Linux系统"
endif

# 完全静态链接（包括系统库）
full-static: $(SOURCES)
ifeq ($(UNAME_S),Linux)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -static -o $(TARGET)_full_static $(SOURCES) -lcurl -lpthread -lssl -lcrypto -lz -ldl
	@echo "完全静态链接版本已创建：$(TARGET)_full_static"
	@echo "这个版本应该在任何Linux系统上都能运行"
else
	@echo "完全静态链接目前只支持Linux系统"
endif

# 安装依赖库的说明
deps:
	@echo "请确保已安装以下依赖库："
	@echo "1. libcurl4-openssl-dev (Ubuntu/Debian) 或 libcurl-devel (CentOS/RHEL)"
	@echo "   Ubuntu/Debian: sudo apt-get install libcurl4-openssl-dev"
	@echo "   CentOS/RHEL: sudo yum install libcurl-devel"
	@echo "   macOS: brew install curl"
	@echo ""
	@echo "2. nlohmann-json (C++ JSON库)"
	@echo "   Ubuntu/Debian: sudo apt-get install nlohmann-json3-dev"
	@echo "   CentOS/RHEL: sudo yum install json-devel"
	@echo "   macOS: brew install nlohmann-json"
	@echo ""
	@echo "如果包管理器中没有nlohmann-json，请手动下载头文件："
	@echo "wget https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp"
	@echo "并将其放在 /usr/local/include/nlohmann/ 目录下"
	@echo ""
	@echo "对于静态链接，还需要安装静态库："
	@echo "Ubuntu/Debian: sudo apt-get install libcurl4-openssl-dev libssl-dev zlib1g-dev"

# 清理
clean:
	rm -f $(TARGET) $(TARGET)_static $(TARGET)_full_static

# 编译并运行测试程序
test: test_build.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o test_build test_build.cpp $(LIBS)
	./test_build
	rm -f test_build

# 运行程序（示例）
run: $(TARGET)
	@echo "请使用以下格式运行程序："
	@echo "./$(TARGET) UUID=your_uuid Client_ID=your_client_id URL=your_server_url"

# 安装
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# 卸载
uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean deps test run install uninstall static full-static 