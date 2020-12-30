Redirection Scripts
===================
My simple scripts used for transparent proxy in many devices. I usually
use them in conjunction with [redsocks2](https://github.com/semigodking/redsocks).

It contains iptables setup for the following functionalities:

* TCP transparent proxy
* UDP transparent proxy (requires TPROXY kernel module)
* Define IP ranges having no transparent proxy applied
* Define IP ranges having Ad filter applied
* Additional rules required by bypass gateway
* White list of IP address ranges
* Black list of IP address ranges

Usage
-----
Run command below to update IP lists first.

```bash
./update_lists.sh
```

Modify scripts in this reop and copy them to your device and invoke the script
`redirect.sh` properly. For example, you can invoke it in `/etc/ppp/ip-up` script
or you can invoke it in `rc.local`.
