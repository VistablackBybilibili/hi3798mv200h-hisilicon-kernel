# Linux 4.4.175 for HiSilicon HI3798MV200H

该内核适配海思HI3798MV200H芯片平台，基于HI3798MV310硬件方案进行移植开发，适用于智能机顶盒

### 特性说明
- 内核版本：Linux 4.4.175
- 处理器架构：ARM64 (Cortex-A53四核)
- 设备树文件：`hi3798mv310.dts` 
- 默认配置：`hi3798mv310_defconfig`
- 编译工具链：`arm-histbv310-linux`

### 编译方法
```bash

# 应用默认配置
make hi3798mv310_defconfig

# 编译内核镜像
make ARCH=arm CROSS_COMPILE=arm-histbv310-linux- -j$(nproc) LOADADDR=0X2000000 uImage modules

# 输出文件路径
# arch/arm64/boot

```bash

# 温馨提示
如果需要使用docker，请参考本仓库根目录的`hi3798mv310_defconfig`的配置文件
