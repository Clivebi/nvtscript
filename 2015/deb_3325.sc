if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703325" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-3183", "CVE-2015-3185" );
	script_name( "Debian Security Advisory DSA 3325-1 (apache2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-01 00:00:00 +0200 (Sat, 01 Aug 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3325.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "apache2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 2.2.22-13+deb7u5.

For the stable distribution (jessie), these problems have been fixed in
version 2.4.10-10+deb8u1.

For the testing distribution (stretch), these problems will be fixed
soon.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your apache2 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been found
in the Apache HTTPD server.
CVE-2015-3183
An HTTP request smuggling attack was possible due to a bug in
parsing of chunked requests. A malicious client could force the
server to misinterpret the request length, allowing cache poisoning
or credential hijacking if an intermediary proxy is in use.

CVE-2015-3185A design error in the ap_some_auth_required function renders the
API unusable in apache2 2.4.x. This could lead to modules using
this API to allow access when they should otherwise not do so.
The fix backports the new ap_some_authn_required
API from 2.4.16.
This issue does not affect the oldstable distribution (wheezy).

In addition, the updated package for the oldstable distribution (wheezy)
removes a limitation of the Diffie-Hellman (DH) parameters to 1024 bits.
This limitation may potentially allow an attacker with very large
computing resources, like a nation-state, to break DH key exchange by
precomputation. The updated apache2 package also allows to configure
custom DH parameters. More information is contained in the
changelog.Debian.gz file.
These improvements were already present in the stable, testing, and
unstable distributions." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "apache2", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-dbg", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-doc", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-event", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-itk", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-prefork", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-worker", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-prefork-dev", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec-custom", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-threaded-dev", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-utils", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2.2-bin", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2.2-common", ver: "2.2.22-13+deb7u5", rls: "DEB7" ) ) != NULL){
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

