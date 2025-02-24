# Linux 4.4.175 for HiSilicon HI3798MV200H

该内核适配海思HI3798MV200H芯片平台，基于HI3798MV310硬件方案进行移植开发，适用于智能机顶盒/边缘计算等场景。

### 特性说明
- 内核版本：Linux 4.4.175
- 处理器架构：ARM64 (Cortex-A53四核)
- 设备树文件：`hi3798mv310.dts` 
- 默认配置：`hi3798mv310_defconfig`

### 编译方法
```bash
# 设置交叉编译环境
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-

# 应用默认配置
make hi3798mv310_defconfig

# 编译内核镜像
make -j$(nproc) Image

# 输出文件路径
# arch/arm64/boot/Image
# arch/arm64/boot/dts/hisilicon/hi3798mv310.dtb<rsup index="2">1</rsup><rsup index="2">3</rsup>
