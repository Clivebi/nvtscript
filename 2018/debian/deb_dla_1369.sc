if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891369" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2017-0861", "CVE-2017-13166", "CVE-2017-16526", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-18017", "CVE-2017-18203", "CVE-2017-18216", "CVE-2017-5715", "CVE-2017-5753", "CVE-2018-1000004", "CVE-2018-1000199", "CVE-2018-1068", "CVE-2018-1092", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5750", "CVE-2018-5803", "CVE-2018-6927", "CVE-2018-7492", "CVE-2018-7566", "CVE-2018-7740", "CVE-2018-7757", "CVE-2018-7995", "CVE-2018-8781", "CVE-2018-8822" );
	script_name( "Debian LTS: Security Advisory for linux (DLA-1369-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-04 00:00:00 +0200 (Fri, 04 May 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-30 21:31:00 +0000 (Fri, 30 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/05/msg00000.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "linux on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.2.101-1. This version also includes bug fixes from upstream versions
up to and including 3.2.101. It also fixes a regression in the
procfs hidepid option in the previous version (Debian bug #887106).

We recommend that you upgrade your linux packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-0861

Robb Glasser reported a potential use-after-free in the ALSA (sound)
PCM core. We believe this was not possible in practice.

CVE-2017-5715

Multiple researchers have discovered a vulnerability in various
processors supporting speculative execution, enabling an attacker
controlling an unprivileged process to read memory from arbitrary
addresses, including from the kernel and all other processes
running on the system.

This specific attack has been named Spectre variant 2 (branch
target injection) and is mitigated for the x86 architecture (amd64
and i386) by using the 'retpoline' compiler feature which allows
indirect branches to be isolated from speculative execution.

CVE-2017-13166

A bug in the 32-bit compatibility layer of the v4l2 ioctl handling
code has been found. Memory protections ensuring user-provided
buffers always point to userland memory were disabled, allowing
destination addresses to be in kernel space. On a 64-bit kernel
(amd64 flavour) a local user with access to a suitable video
device can exploit this to overwrite kernel memory, leading to
privilege escalation.

Description truncated. Please see the references for more information." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "linux-doc-3.2", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-486", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all-armel", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all-armhf", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-all-i386", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-common", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-common-rt", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-iop32x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-ixp4xx", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-kirkwood", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-mv78xx0", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-mx5", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-omap", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-orion5x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-rt-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-rt-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-versatile", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-4-vexpress", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-486", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-all", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-all-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-all-armel", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-all-armhf", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-all-i386", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-common", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-common-rt", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-iop32x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-ixp4xx", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-kirkwood", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-mv78xx0", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-mx5", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-omap", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-orion5x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-rt-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-rt-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-versatile", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-5-vexpress", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-486", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-all", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-all-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-all-armel", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-all-armhf", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-all-i386", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-common", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-common-rt", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-iop32x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-ixp4xx", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-kirkwood", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-mv78xx0", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-mx5", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-omap", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-orion5x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-rt-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-rt-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-versatile", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.2.0-6-vexpress", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-486", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-686-pae-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-amd64-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-iop32x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-ixp4xx", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-kirkwood", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-mv78xx0", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-mx5", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-omap", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-orion5x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-rt-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-rt-686-pae-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-rt-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-rt-amd64-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-versatile", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-4-vexpress", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-486", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-686-pae-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-amd64-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-iop32x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-ixp4xx", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-kirkwood", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-mv78xx0", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-mx5", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-omap", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-orion5x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-rt-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-rt-686-pae-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-rt-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-rt-amd64-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-versatile", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-5-vexpress", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-486", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-686-pae-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-amd64-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-iop32x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-ixp4xx", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-kirkwood", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-mv78xx0", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-mx5", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-omap", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-orion5x", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-rt-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-rt-686-pae-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-rt-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-rt-amd64-dbg", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-versatile", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.2.0-6-vexpress", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-manual-3.2", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-source-3.2", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.2.0-4", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.2.0-5", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.2.0-6", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.2.0-4-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.2.0-4-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.2.0-5-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.2.0-5-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.2.0-6-686-pae", ver: "3.2.101-1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.2.0-6-amd64", ver: "3.2.101-1", rls: "DEB7" ) )){
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

