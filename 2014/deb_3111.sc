if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703111" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-9112" );
	script_name( "Debian Security Advisory DSA 3111-1 (cpio - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-12-22 00:00:00 +0100 (Mon, 22 Dec 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3111.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "cpio on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 2.11+dfsg-0.1+deb7u1.

For the upcoming stable distribution (jessie), this problem will be
fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 2.11+dfsg-4.

We recommend that you upgrade your cpio packages." );
	script_tag( name: "summary", value: "Michal Zalewski discovered
an out of bounds write issue in cpio, a tool for creating and extracting cpio
archive files. In the process of fixing that issue, the cpio developers found
and fixed additional range checking and null pointer dereference issues." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cpio", ver: "2.11+dfsg-0.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cpio-win32", ver: "2.11+dfsg-0.1+deb7u1", rls: "DEB7" ) ) != NULL){
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

