if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703098" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-9157" );
	script_name( "Debian Security Advisory DSA 3098-1 (graphviz - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-12-11 00:00:00 +0100 (Thu, 11 Dec 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3098.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "graphviz on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 2.26.3-14+deb7u2.

For the upcoming stable distribution (jessie), this problem will be
fixed soon in version 2.38.0-7.

For the unstable distribution (sid), this problem has been fixed in
version 2.38.0-7.

We recommend that you upgrade your graphviz packages." );
	script_tag( name: "summary", value: "Joshua Rogers discovered a format
string vulnerability in the yyerror function in lib/cgraph/scan.l in Graphviz,
a rich set of graph drawing tools. An attacker could use this flaw to cause
graphviz to crash or possibly execute arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "graphviz", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "graphviz-dev", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "graphviz-doc", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcdt4", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcgraph5", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraph4", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphviz-dev", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgv-guile", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgv-lua", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgv-perl", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgv-php5", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgv-python", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgv-ruby", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgv-tcl", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgvc5", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgvc5-plugins-gtk", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgvpr1", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpathplan4", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxdot4", ver: "2.26.3-14+deb7u2", rls: "DEB7" ) ) != NULL){
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

