if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702791" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4510" );
	script_name( "Debian Security Advisory DSA 2791-1 (tryton-client - missing input sanitization)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-11-04 00:00:00 +0100 (Mon, 04 Nov 2013)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:C/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2791.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "tryton-client on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.6.1-1+deb6u1.

For the stable distribution (wheezy), this problem has been fixed in
version 2.2.3-1+deb7u1.

We recommend that you upgrade your tryton-client packages." );
	script_tag( name: "summary", value: "Cedric Krier discovered that the Tryton client does not sanitize the
file extension supplied by the server when processing reports. As a
result, a malicious server could send a report with a crafted file
extension that causes the client to write any local file to which the
user running the client has write access." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "tryton-client", ver: "1.6.1-1+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tryton-client", ver: "2.2.3-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

