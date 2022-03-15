if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704760" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-12829", "CVE-2020-14364", "CVE-2020-15863", "CVE-2020-16092" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-11 06:15:00 +0000 (Wed, 11 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-09-08 03:00:49 +0000 (Tue, 08 Sep 2020)" );
	script_name( "Debian: Security Advisory for qemu (DSA-4760-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4760.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4760-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the DSA-4760-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in QEMU, a fast processor
emulator:

CVE-2020-12829
An integer overflow in the sm501 display device may result in denial of
service.

CVE-2020-14364
An out-of-bounds write in the USB emulation code may result in
guest-to-host code execution.

CVE-2020-15863
A buffer overflow in the XGMAC network device may result in denial of
service or the execution of arbitrary code.

CVE-2020-16092
A triggerable assert in the e1000e and vmxnet3 devices may result in
denial of service." );
	script_tag( name: "affected", value: "'qemu' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 1:3.1+dfsg-8+deb10u8.

We recommend that you upgrade your qemu packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-block-extra", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-guest-agent", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-common", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-data", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-gui", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user-binfmt", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-utils", ver: "1:3.1+dfsg-8+deb10u8", rls: "DEB10" ) )){
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

