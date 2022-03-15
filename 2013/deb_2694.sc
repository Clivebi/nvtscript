if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702694" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-2118" );
	script_name( "Debian Security Advisory DSA 2694-1 (spip - privilege escalation)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-05-26 00:00:00 +0200 (Sun, 26 May 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2694.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "spip on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 2.1.1-3squeeze6.

For the stable distribution (wheezy), this problem has been fixed in
version 2.1.17-1+deb7u1.

For the testing distribution (jessie), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 2.1.22-1.

We recommend that you upgrade your spip packages." );
	script_tag( name: "summary", value: "A privilege escalation vulnerability has been found in SPIP, a website
engine for publishing, which allows anyone to take control of the
website." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "spip", ver: "2.1.1-3squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spip", ver: "2.1.17-1+deb7u1", rls: "DEB7" ) ) != NULL){
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
