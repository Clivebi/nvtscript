if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703991" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2017-12809", "CVE-2017-13672", "CVE-2017-13711", "CVE-2017-14167", "CVE-2017-9375" );
	script_name( "Debian Security Advisory DSA 3991-1 (qemu - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-03 00:00:00 +0200 (Tue, 03 Oct 2017)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 20:21:00 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3991.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "qemu on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1:2.8+dfsg-6+deb9u3.

We recommend that you upgrade your qemu packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were found in qemu, a fast processor emulator:

CVE-2017-9375
Denial of service via memory leak in USB XHCI emulation.

CVE-2017-12809
Denial of service in the CDROM device drive emulation.

CVE-2017-13672
Denial of service in VGA display emulation.

CVE-2017-13711
Denial of service in SLIRP networking support.

CVE-2017-14167
Incorrect validation of multiboot headers could result in the
execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "qemu", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-block-extra", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-guest-agent", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-system", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-system-common", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-user", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-user-binfmt", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-utils", ver: "1:2.8+dfsg-6+deb9u3", rls: "DEB9" ) ) != NULL){
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

