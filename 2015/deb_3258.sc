if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703258" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2013-4422", "CVE-2015-3427" );
	script_name( "Debian Security Advisory DSA 3258-1 (quassel - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-05-12 00:00:00 +0200 (Tue, 12 May 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3258.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "quassel on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 1:0.10.0-2.3+deb8u1.

For the testing distribution (stretch), this problem has been fixed in
version 1:0.10.0-2.4.

For the unstable distribution (sid), this problem has been fixed in
version 1:0.10.0-2.4.

We recommend that you upgrade your quassel packages." );
	script_tag( name: "summary", value: "It was discovered that the fix for
CVE-2013-4422
in quassel, a
distributed IRC client, was incomplete. This could allow remote
attackers to inject SQL queries after a database reconnection (e.g.
when the backend PostgreSQL server is restarted)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "quassel", ver: "1:0.10.0-2.4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-client", ver: "1:0.10.0-2.4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-client-kde4", ver: "1:0.10.0-2.4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-core", ver: "1:0.10.0-2.4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-data", ver: "1:0.10.0-2.4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-kde4", ver: "1:0.10.0-2.4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel", ver: "1:0.10.0-2.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-client", ver: "1:0.10.0-2.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-client-kde4", ver: "1:0.10.0-2.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-core", ver: "1:0.10.0-2.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-data", ver: "1:0.10.0-2.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-data-kde4", ver: "1:0.10.0-2.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-kde4", ver: "1:0.10.0-2.3+deb8u1", rls: "DEB8" ) ) != NULL){
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

