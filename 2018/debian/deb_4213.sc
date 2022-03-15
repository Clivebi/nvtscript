if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704213" );
	script_version( "2021-06-21T03:34:17+0000" );
	script_cve_id( "CVE-2017-15038", "CVE-2017-15119", "CVE-2017-15124", "CVE-2017-15268", "CVE-2017-15289", "CVE-2017-16845", "CVE-2017-17381", "CVE-2017-18043", "CVE-2017-5715", "CVE-2018-5683", "CVE-2018-7550" );
	script_name( "Debian Security Advisory DSA 4213-1 (qemu - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-29 00:00:00 +0200 (Tue, 29 May 2018)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-31 10:29:00 +0000 (Wed, 31 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4213.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "qemu on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1:2.8+dfsg-6+deb9u4.

We recommend that you upgrade your qemu packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/qemu" );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in qemu, a fast processor
emulator.

CVE-2017-15038
Tuomas Tynkkynen discovered an information leak in 9pfs.

CVE-2017-15119
Eric Blake discovered that the NBD server insufficiently restricts
large option requests, resulting in denial of service.

CVE-2017-15124
Daniel Berrange discovered that the integrated VNC server
insufficiently restricted memory allocation, which could result in
denial of service.

CVE-2017-15268
A memory leak in websockets support may result in denial of service.

CVE-2017-15289
Guoxiang Niu discovered an OOB write in the emulated Cirrus graphics
adaptor which could result in denial of service.

CVE-2017-16845
Cyrille Chatras discovered an information leak in PS/2 mouse and
keyboard emulation which could be exploited during instance
migration.

CVE-2017-17381
Dengzhan Heyuandong Bijunhua and Liweichao discovered that an
implementation error in the virtio vring implementation could result
in denial of service.

CVE-2017-18043
Eric Blake discovered an integer overflow in an internally used
macro which could result in denial of service.

CVE-2018-5683
Jiang Xin and Lin ZheCheng discovered an OOB memory access in the
emulated VGA adaptor which could result in denial of service.

CVE-2018-7550
Cyrille Chatras discovered that an OOB memory write when using
multiboot could result in the execution of arbitrary code.

This update also backports a number of mitigations against the Spectre
v2 vulnerability affecting modern CPUs
(CVE-2017-5715). For additional information please" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_xref( name: "URL", value: "https://www.qemu.org/2018/01/04/spectre/" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-block-extra", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-guest-agent", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-common", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user-binfmt", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-utils", ver: "1:2.8+dfsg-6+deb9u4", rls: "DEB9" ) )){
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

