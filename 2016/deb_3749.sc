if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703749" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2015-8979" );
	script_name( "Debian Security Advisory DSA 3749-1 (dcmtk - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-12-29 00:00:00 +0100 (Thu, 29 Dec 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3749.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "dcmtk on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this
problem has been fixed in version 3.6.0-15+deb8u1.

For the testing (stretch) and unstable (sid) distributions, this
problem has been fixed in version 3.6.1~20160216-2.

We recommend that you upgrade your dcmtk packages." );
	script_tag( name: "summary", value: "Gjoko Krstic of Zero Science Labs
discovered that dcmtk, a collection of libraries implementing the DICOM standard, did
not properly handle the size of data received from the network. This could lead to
denial-of-service (via application crash) or arbitrary code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dcmtk", ver: "3.6.0-15+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dcmtk-doc", ver: "3.6.0-15+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dcmtk-www", ver: "3.6.0-15+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdcmtk2", ver: "3.6.0-15+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdcmtk2-dbg", ver: "3.6.0-15+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdcmtk2-dev", ver: "3.6.0-15+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dcmtk", ver: "3.6.1~20160216-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dcmtk-doc", ver: "3.6.1~20160216-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdcmtk-dev", ver: "3.6.1~20160216-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdcmtk8", ver: "3.6.1~20160216-2", rls: "DEB9" ) ) != NULL){
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

