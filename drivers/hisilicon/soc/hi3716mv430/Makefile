ccflags-y += -I$(srctree)

obj-y += cpu-hi3716mv430.o
obj-y += hiplat_common.o
obj-$(CONFIG_PM) += hipm_check.o
obj-$(CONFIG_PM) += bootreg_resume.o
obj-$(CONFIG_PM) += hipm_sleep.o
obj-$(CONFIG_PM) += hipm.o
obj-$(CONFIG_CPU_IDLE_HI3716MV430) 	+= cpuidle-hi3716mv430.o pm-hi3716mv430.o
