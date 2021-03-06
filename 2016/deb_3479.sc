if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703479" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523" );
	script_name( "Debian Security Advisory DSA 3479-1 (graphite2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-02-15 00:00:00 +0100 (Mon, 15 Feb 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3479.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9|7)" );
	script_tag( name: "affected", value: "graphite2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1.3.5-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 1.3.5-1~deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 1.3.5-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.3.5-1.

We recommend that you upgrade your graphite2 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been
found in the Graphite font rendering engine which might result in denial of
service or the execution of arbitrary code if a malformed font file is
processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libgraphite2-3:amd64", ver: "1.3.5-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-3:i386", ver: "1.3.5-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-3-dbg", ver: "1.3.5-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-dev", ver: "1.3.5-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-doc", ver: "1.3.5-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-3:amd64", ver: "1.3.5-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-3:i386", ver: "1.3.5-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-dev", ver: "1.3.5-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-doc", ver: "1.3.5-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-2.0.0", ver: "1.3.5-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-2.0.0-dbg", ver: "1.3.5-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-dev", ver: "1.3.5-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgraphite2-doc", ver: "1.3.5-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

