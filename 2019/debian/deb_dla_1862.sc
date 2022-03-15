if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891862" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-10639", "CVE-2019-13272", "CVE-2019-2101" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-02 15:42:00 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-07-24 02:00:09 +0000 (Wed, 24 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for linux (DLA-1862-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00022.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1862-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/930904" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the DLA-1862-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2019-2101

Andrey Konovalov discovered that the USB Video Class driver
(uvcvideo) did not consistently handle a type field in device
descriptors, which could result in a heap buffer overflow. This
could be used for denial of service or possibly for privilege
escalation.

CVE-2019-10639

Amit Klein and Benny Pinkas discovered that the generation of IP
packet IDs used a weak hash function that incorporated a kernel
virtual address. In Linux 3.16 this hash function is not used for
IP IDs but is used for other purposes in the network stack. In
custom kernel configurations that enable kASLR, this might weaken
kASLR.

CVE-2019-13272

Jann Horn discovered that the ptrace subsystem in the Linux kernel
mishandles the management of the credentials of a process that wants
to create a ptrace relationship, allowing a local user to obtain root
privileges under certain scenarios." );
	script_tag( name: "affected", value: "'linux' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.16.70-1. This update also fixes a regression introduced by the
original fix for CVE-2019-11478 (#930904), and includes other fixes
from upstream stable updates.

We recommend that you upgrade your linux and linux-latest
packages. You will need to use 'apt-get upgrade --with-new-pkgs'
or 'apt upgrade' as the binary package names have changed.

We recommend that you upgrade your linux packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-arm", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.8-x86", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.9-x86", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-doc-3.16", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-all", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-all-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-all-i386", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-10-common", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-armel", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-armhf", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-all-i386", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-common", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-4-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-armel", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-armhf", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-all-i386", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-common", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-5-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-armel", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-armhf", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-all-i386", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-common", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-6-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-all", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-all-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-all-armel", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-all-armhf", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-all-i386", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-common", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-7-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-all", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-all-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-all-armel", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-all-armhf", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-all-i386", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-common", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-8-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-all", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-all-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-all-armel", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-all-armhf", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-all-i386", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-common", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-3.16.0-9-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-686-pae-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-10-amd64-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-686-pae-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-amd64-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-4-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-686-pae-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-amd64-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-5-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-686-pae-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-amd64-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-6-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-7-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-7-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-7-686-pae-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-7-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-7-amd64-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-7-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-7-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-7-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-7-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-7-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-7-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-8-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-8-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-8-686-pae-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-8-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-8-amd64-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-8-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-8-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-8-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-8-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-8-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-8-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-9-586", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-9-686-pae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-9-686-pae-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-9-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-9-amd64-dbg", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-9-armmp", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-9-armmp-lpae", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-9-ixp4xx", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-9-kirkwood", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-9-orion5x", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-3.16.0-9-versatile", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-manual-3.16", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-source-3.16", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-10", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-4", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-6", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-7", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-8", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-3.16.0-9", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-10-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-4-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-5-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-6-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-7-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-8-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-linux-system-3.16.0-9-amd64", ver: "3.16.70-1", rls: "DEB8" ) )){
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

