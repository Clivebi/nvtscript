if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702611" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-0209" );
	script_name( "Debian Security Advisory DSA 2611-1 (movabletype-opensource - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-01-22 00:00:00 +0100 (Tue, 22 Jan 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2611.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "movabletype-opensource on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 4.3.8+dfsg-0+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in
version 5.1.2+dfsg-1.

For the unstable distribution (sid), this problem has been fixed in
version 5.1.2+dfsg-1.

We recommend that you upgrade your movabletype-opensource packages." );
	script_tag( name: "summary", value: "An input sanitation problem has been found in upgrade functions of
movabletype-opensource, a web-based publishing platform. Using carefully
crafted requests to the mt-upgrade.cgi file, it would be possible to inject OS
command and SQL queries." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "movabletype-opensource", ver: "4.3.8+dfsg-0+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-plugin-core", ver: "4.3.8+dfsg-0+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-plugin-zemanta", ver: "4.3.8+dfsg-0+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-opensource", ver: "5.1.2+dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-plugin-core", ver: "5.1.2+dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-plugin-zemanta", ver: "5.1.2+dfsg-1", rls: "DEB7" ) ) != NULL){
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

