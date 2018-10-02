# webcam-interception-driver

A complementary sample driver for the article: [Through the looking glass: webcam interception and protection in kernel mode](https://www.virusbulletin.com/virusbulletin/2018/09/through-looking-glass-webcam-interception-and-protection-kernel-mode/).

The driver demonstrates the following functionality:
* Verbose camera-related IRP logging.
* Blocking `KSSTATE_ACQUIRE` (`IOCTL_KS_PROPERTY`).
* Intercepting `IOCTL_KS_READ_STREAM`.
