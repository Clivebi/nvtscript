if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703679" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-6801" );
	script_name( "Debian Security Advisory DSA 3679-1 (jackrabbit - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-10-05 15:43:22 +0530 (Wed, 05 Oct 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3679.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "jackrabbit on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this
problem has been fixed in version 2.3.6-1+deb8u2.

For the unstable distribution (sid), this problem has been fixed in
version 2.12.4-1.

We recommend that you upgrade your jackrabbit packages." );
	script_tag( name: "summary", value: "Lukas Reschke discovered that Apache
Jackrabbit, an implementation of the Content Repository for Java Technology API,
did not correctly check the Content-Type header on HTTP POST requests, enabling
Cross-Site Request Forgery (CSRF) attacks by malicious web sites." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libjackrabbit-java", ver: "2.3.6-1+deb8u2", rls: "DEB8" ) ) != NULL){
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

