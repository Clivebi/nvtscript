if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704843" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2020-27815", "CVE-2020-27825", "CVE-2020-27830", "CVE-2020-28374", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158", "CVE-2021-20177", "CVE-2021-3347" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-02-03 04:00:12 +0000 (Wed, 03 Feb 2021)" );
	script_name( "Debian: Security Advisory for linux (DSA-4843-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4843.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4843-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4843-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the DSA-4843-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2020-27815
A flaw was reported in the JFS filesystem code allowing a local
attacker with the ability to set extended attributes to cause a
denial of service.

CVE-2020-27825Adam pi3
Zabrocki reported a use-after-free flaw in the ftrace
ring buffer resizing logic due to a race condition, which could
result in denial of service or information leak.

CVE-2020-27830
Shisong Qin reported a NULL pointer dereference flaw in the Speakup
screen reader core driver.

CVE-2020-28374
David Disseldorp discovered that the LIO SCSI target implementation
performed insufficient checking in certain XCOPY requests. An
attacker with access to a LUN and knowledge of Unit Serial Number
assignments can take advantage of this flaw to read and write to any
LIO backstore, regardless of the SCSI transport settings.

CVE-2020-29568 (XSA-349)
Michael Kurth and Pawel Wieczorkiewicz reported that frontends can
trigger OOM in backends by updating a watched path.

CVE-2020-29569 (XSA-350)
Olivier Benjamin and Pawel Wieczorkiewicz reported a use-after-free
flaw which can be triggered by a block frontend in Linux blkback. A
misbehaving guest can trigger a dom0 crash by continuously
connecting / disconnecting a block frontend.

CVE-2020-29660
Jann Horn reported a locking inconsistency issue in the tty
subsystem which may allow a local attacker to mount a
read-after-free attack against TIOCGSID.

CVE-2020-29661
Jann Horn reported a locking issue in the tty subsystem which can
result in a use-after-free. A local attacker can take advantage of
this flaw for memory corruption or privilege escalation.

CVE-2020-36158
A buffer overflow flaw was discovered in the mwifiex WiFi driver
which could result in denial of service or the execution of
arbitrary code via a long SSID value.

CVE-2021-3347
It was discovered that PI futexes have a kernel stack use-after-free
during fault handling. An unprivileged user could use this flaw to
crash the kernel (resulting in denial of service) or for privilege
escalation.

CVE-2021-20177
A flaw was discovered in the Linux implementation of string matching
within a packet. A privileged user (with root or CAP_NET_ADMIN) can
take advantage of this flaw to cause a kernel panic when inserting
iptables rules." );
	script_tag( name: "affected", value: "'linux' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 4.19.171-2.

We recommend that you upgrade your linux packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "hyperv-daemons", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbpf-dev", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbpf4.19", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcpupower-dev", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcpupower1", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblockdep-dev", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblockdep4.19", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-8-arm", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-8-s390", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-8-x86", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-config-4.19", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-cpupower", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-doc-4.19", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-4kc-malta", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-5kc-malta", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-686", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-686-pae", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-all", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-all-amd64", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-all-arm64", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-all-armel", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-all-armhf", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-all-i386", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-all-mips", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-all-mips64el", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-all-mipsel", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-all-ppc64el", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-all-s390x", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-amd64", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-arm64", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-armmp", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-armmp-lpae", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-cloud-amd64", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-common", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-common-rt", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-loongson-3", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-marvell", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-octeon", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-powerpc64le", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-rpi", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-rt-686-pae", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-rt-amd64", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-rt-arm64", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-rt-armmp", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.19.0-14-s390x", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-4kc-malta", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-4kc-malta-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-5kc-malta", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-5kc-malta-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-686-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-686-pae-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-686-pae-unsigned", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-686-unsigned", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-amd64-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-amd64-unsigned", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-arm64-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-arm64-unsigned", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-armmp", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-armmp-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-armmp-lpae", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-armmp-lpae-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-cloud-amd64-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-cloud-amd64-unsigned", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-loongson-3", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-loongson-3-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-marvell", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-marvell-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-octeon", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-octeon-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-powerpc64le", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-powerpc64le-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-rpi", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-rpi-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-rt-686-pae-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-rt-686-pae-unsigned", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-rt-amd64-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-rt-amd64-unsigned", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-rt-arm64-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-rt-arm64-unsigned", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-rt-armmp", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-rt-armmp-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-s390x", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.19.0-14-s390x-dbg", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-amd64-signed-template", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-arm64-signed-template", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-i386-signed-template", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-kbuild-4.19", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-perf-4.19", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-source-4.19", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-4.19.0-14", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lockdep", ver: "4.19.171-2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "usbip", ver: "4.19.171-2", rls: "DEB10" ) )){
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
exit( 0 );

