if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703205" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-0250" );
	script_name( "Debian Security Advisory DSA 3205-1 (batik - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-27 00:00:00 +0100 (Fri, 27 Mar 2015)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3205.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "batik on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.7+dfsg-3+deb7u1.

For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version 1.7+dfsg-5.

We recommend that you upgrade your batik packages." );
	script_tag( name: "summary", value: "Nicolas Gregoire and Kevin Schaller
discovered that Batik, a toolkit for processing SVG images, would load XML
external entities by default. If a user or automated system were tricked into
opening a specially crafted SVG file, an attacker could possibly obtain access
to arbitrary files or cause resource consumption." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libbatik-java", ver: "1.7+dfsg-3+deb7u1", rls: "DEB7" ) ) != NULL){
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

