if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703553" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2015-8852" );
	script_name( "Debian Security Advisory DSA 3553-1 (varnish - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-22 00:00:00 +0200 (Fri, 22 Apr 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3553.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "varnish on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 3.0.2-2+deb7u2.

We recommend that you upgrade your varnish packages." );
	script_tag( name: "summary", value: "Regis Leroy from Makina Corpus discovered
that varnish, a caching HTTP reverse proxy, is vulnerable to HTTP smuggling issues,
potentially resulting in cache poisoning or bypassing of access control policies." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libvarnishapi-dev", ver: "3.0.2-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvarnishapi1", ver: "3.0.2-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "varnish", ver: "3.0.2-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "varnish-dbg", ver: "3.0.2-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "varnish-doc", ver: "3.0.2-2+deb7u2", rls: "DEB7" ) ) != NULL){
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

