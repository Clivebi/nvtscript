if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72174" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-2652", "CVE-2012-3515" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-15 04:24:19 -0400 (Sat, 15 Sep 2012)" );
	script_name( "Debian Security Advisory DSA 2545-1 (qemu)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202545-1" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in qemu, a fast processor
emulator. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2012-2652:

The snapshot mode of QEMU (-snapshot) incorrectly handles temporary
files used to store the current state, making it vulnerable to
symlink attacks (including arbitrary file overwriting and guest
information disclosure) due to a race condition.

CVE-2012-3515:

QEMU does not properly handle VT100 escape sequences when emulating
certain devices with a virtual console backend. An attacker within a
guest with access to the vulnerable virtual console could overwrite
memory of QEMU and escalate privileges to that of the qemu process.

For the stable distribution (squeeze), these problems have been fixed in
version 0.12.5+dfsg-3squeeze2.

For the testing distribution (wheezy), and the unstable distribution
(sid), these problems will been fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your qemu packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to qemu
announced via advisory DSA 2545-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libqemu-dev", ver: "0.12.5+dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu", ver: "0.12.5+dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-keymaps", ver: "0.12.5+dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-system", ver: "0.12.5+dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-user", ver: "0.12.5+dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-user-static", ver: "0.12.5+dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-utils", ver: "0.12.5+dfsg-3squeeze2", rls: "DEB6" ) ) != NULL){
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

