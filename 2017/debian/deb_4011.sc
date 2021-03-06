if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704011" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-16227" );
	script_name( "Debian Security Advisory DSA 4011-1 (quagga - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-30 00:00:00 +0100 (Mon, 30 Oct 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-18 16:16:00 +0000 (Sat, 18 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-4011.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "quagga on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 0.99.23.1-1+deb8u4.

For the stable distribution (stretch), this problem has been fixed in
version 1.1.1-3+deb9u1.

We recommend that you upgrade your quagga packages." );
	script_tag( name: "summary", value: "It was discovered that the bgpd daemon in the Quagga routing suite does
not properly calculate the length of multi-segment AS_PATH UPDATE
messages, causing bgpd to drop a session and potentially resulting in
loss of network connectivity." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "quagga", ver: "1.1.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga-bgpd", ver: "1.1.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga-core", ver: "1.1.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga-doc", ver: "1.1.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga-isisd", ver: "1.1.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga-ospf6d", ver: "1.1.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga-ospfd", ver: "1.1.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga-pimd", ver: "1.1.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga-ripd", ver: "1.1.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga-ripngd", ver: "1.1.1-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga", ver: "0.99.23.1-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga-dbg", ver: "0.99.23.1-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quagga-doc", ver: "0.99.23.1-1+deb8u4", rls: "DEB8" ) ) != NULL){
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

