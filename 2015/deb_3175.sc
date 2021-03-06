if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703175" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-1414" );
	script_name( "Debian Security Advisory DSA 3175-1 (kfreebsd-9 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-25 00:00:00 +0100 (Wed, 25 Feb 2015)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3175.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "kfreebsd-9 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 9.0-10+deb70.9.

We recommend that you upgrade your kfreebsd-9 packages." );
	script_tag( name: "summary", value: "Mateusz Kocielski and Marek Kroemeke
discovered that an integer overflow in IGMP processing may result in denial of
service through malformed IGMP packets." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9-486", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9-686", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9-686-smp", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9-amd64", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9-malta", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9-xen", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9.0-2", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9.0-2-486", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9.0-2-686", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9.0-2-686-smp", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9.0-2-amd64", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9.0-2-malta", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-headers-9.0-2-xen", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9-486", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9-686", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9-686-smp", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9-amd64", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9-malta", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9-xen", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9.0-2-486", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9.0-2-686", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9.0-2-686-smp", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9.0-2-amd64", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9.0-2-malta", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-image-9.0-2-xen", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "kfreebsd-source-9.0", ver: "9.0-10+deb70.9", rls: "DEB7" ) ) != NULL){
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

