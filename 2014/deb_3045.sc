if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703045" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0142", "CVE-2014-0143", "CVE-2014-0144", "CVE-2014-0145", "CVE-2014-0146", "CVE-2014-0147", "CVE-2014-0222", "CVE-2014-0223", "CVE-2014-3615", "CVE-2014-3640" );
	script_name( "Debian Security Advisory DSA 3045-1 (qemu - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-10-04 00:00:00 +0200 (Sat, 04 Oct 2014)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3045.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "qemu on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 1.1.2+dfsg-6a+deb7u4.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your qemu packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in qemu, a fast processor
emulator:

Various security issues have been found in the block qemu drivers.
Malformed disk images might result in the execution of arbitrary code.A NULL pointer dereference in SLIRP may result in denial of serviceAn information leak was discovered in the VGA emulation" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "qemu", ver: "1.1.2+dfsg-6a+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-keymaps", ver: "1.1.2+dfsg-6a+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-system", ver: "1.1.2+dfsg-6a+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-user", ver: "1.1.2+dfsg-6a+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1.1.2+dfsg-6a+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-utils", ver: "1.1.2+dfsg-6a+deb7u4", rls: "DEB7" ) ) != NULL){
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

