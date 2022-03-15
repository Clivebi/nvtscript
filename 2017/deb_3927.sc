if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703927" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_cve_id( "CVE-2017-1000365", "CVE-2017-10810", "CVE-2017-10911", "CVE-2017-11176", "CVE-2017-7346", "CVE-2017-7482", "CVE-2017-7533", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-9605" );
	script_name( "Debian Security Advisory DSA 3927-1 (linux - security update)" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-07 00:00:00 +0200 (Mon, 07 Aug 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3927.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "linux on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems will be fixed in
a subsequent DSA.

For the stable distribution (stretch), these problems have been fixed in
version 4.9.30-2+deb9u3.

We recommend that you upgrade your linux packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-7346
Li Qiang discovered that the DRM driver for VMware virtual GPUs does
not properly check user-controlled values in the
vmw_surface_define_ioctl() functions for upper limits. A local user
can take advantage of this flaw to cause a denial of service.

CVE-2017-7482
Shi Lei discovered that RxRPC Kerberos 5 ticket handling code does
not properly verify metadata, leading to information disclosure,
denial of service or potentially execution of arbitrary code.

CVE-2017-7533
Fan Wu and Shixiong Zhao discovered a race condition between inotify
events and VFS rename operations allowing an unprivileged local
attacker to cause a denial of service or escalate privileges.

CVE-2017-7541
A buffer overflow flaw in the Broadcom IEEE802.11n PCIe SoftMAC WLAN
driver could allow a local user to cause kernel memory corruption,
leading to a denial of service or potentially privilege escalation.

CVE-2017-7542
An integer overflow vulnerability in the ip6_find_1stfragopt()
function was found allowing a local attacker with privileges to open
raw sockets to cause a denial of service.

CVE-2017-9605
Murray McAllister discovered that the DRM driver for VMware virtual
GPUs does not properly initialize memory, potentially allowing a
local attacker to obtain sensitive information from uninitialized
kernel memory via a crafted ioctl call.

CVE-2017-10810
Li Qiang discovered a memory leak flaw within the VirtIO GPU driver
resulting in denial of service (memory consumption).

CVE-2017-10911 /
XSA-216
Anthony Perard of Citrix discovered an information leak flaw in Xen
blkif response handling, allowing a malicious unprivileged guest to
obtain sensitive information from the host or other guests.

CVE-2017-11176
It was discovered that the mq_notify() function does not set the
sock pointer to NULL upon entry into the retry logic. An attacker
can take advantage of this flaw during a user-space close of a
Netlink socket to cause a denial of service or potentially cause
other impact.

CVE-2017-1000365
It was discovered that argument and environment pointers are not
taken properly into account to the imposed size restrictions on
arguments and environmental strings passed through
RLIMIT_STACK/RLIMIT_INFINITY. A local attacker can take advantage of
this flaw in conjunction with other flaws to execute arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "hyperv-daemons", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcpupower-dev", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcpupower1", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libusbip-dev", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-compiler-gcc-6-arm", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-compiler-gcc-6-s390", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-compiler-gcc-6-x86", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-cpupower", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-doc-4.9", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-4kc-malta", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-5kc-malta", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-686", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-686-pae", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-amd64", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-arm64", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-armel", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-armhf", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-i386", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-mips", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-mips64el", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-mipsel", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-ppc64el", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-all-s390x", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-amd64", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-arm64", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-armmp", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-armmp-lpae", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-common", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-common-rt", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-loongson-3", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-marvell", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-octeon", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-powerpc64le", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-rt-686-pae", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-rt-amd64", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-headers-4.9.0-3-s390x", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-4kc-malta", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-4kc-malta-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-5kc-malta", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-5kc-malta-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-686", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-686-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-686-pae", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-686-pae-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-amd64", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-amd64-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-arm64", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-arm64-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-armmp", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-armmp-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-armmp-lpae", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-armmp-lpae-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-loongson-3", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-loongson-3-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-marvell", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-marvell-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-octeon", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-octeon-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-powerpc64le", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-powerpc64le-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-rt-686-pae", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-rt-686-pae-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-rt-amd64", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-rt-amd64-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-s390x", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-image-4.9.0-3-s390x-dbg", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-kbuild-4.9", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-manual-4.9", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-perf-4.9", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-source-4.9", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "linux-support-4.9.0-3", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "usbip", ver: "4.9.30-2+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

