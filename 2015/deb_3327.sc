if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703327" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-5400" );
	script_name( "Debian Security Advisory DSA 3327-1 (squid3 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-03 00:00:00 +0200 (Mon, 03 Aug 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3327.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "squid3 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 3.1.20-2.2+deb7u3.

For the stable distribution (jessie), this problem has been fixed in
version 3.4.8-6+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 3.5.6-1.

We recommend that you upgrade your squid3 packages." );
	script_tag( name: "summary", value: "Alex Rousskov of The Measurement Factory
discovered that Squid3, a fully featured web proxy cache, does not correctly handle
CONNECT method peer responses when configured with cache_peer and operating on
explicit proxy traffic. This could allow remote clients to gain unrestricted
access through a gateway proxy to its backend proxy." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.1.20-2.2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3", ver: "3.1.20-2.2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3-common", ver: "3.1.20-2.2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3-dbg", ver: "3.1.20-2.2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squidclient", ver: "3.1.20-2.2+deb7u3", rls: "DEB7" ) ) != NULL){
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

