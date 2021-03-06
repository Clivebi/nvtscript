if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703483" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-2037" );
	script_name( "Debian Security Advisory DSA 3483-1 (cpio - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-02-19 00:00:00 +0100 (Fri, 19 Feb 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3483.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "cpio on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 2.11+dfsg-0.1+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 2.11+dfsg-4.1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 2.11+dfsg-5.

We recommend that you upgrade your cpio packages." );
	script_tag( name: "summary", value: "Gustavo Grieco discovered an out-of-bounds
write vulnerability in cpio, a tool for creating and extracting cpio archive files,
leading to a denial of service (application crash)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cpio", ver: "2.11+dfsg-0.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cpio-win32", ver: "2.11+dfsg-0.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cpio", ver: "2.11+dfsg-4.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cpio-win32", ver: "2.11+dfsg-4.1+deb8u1", rls: "DEB8" ) ) != NULL){
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

