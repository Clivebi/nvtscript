if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703745" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-10002" );
	script_name( "Debian Security Advisory DSA 3745-1 (squid3 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-12-24 00:00:00 +0100 (Sat, 24 Dec 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3745.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "squid3 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 3.4.8-6+deb8u4.

For the unstable distribution (sid), this problem has been fixed in
version 3.5.23-1.

We recommend that you upgrade your squid3 packages." );
	script_tag( name: "summary", value: "Saulius Lapinskas from Lithuanian
State Social Insurance Fund Board discovered that Squid3, a fully featured web
proxy cache, does not properly process responses to If-None-Modified HTTP
conditional requests, leading to client-specific Cookie data being leaked to other
clients. A remote attacker can take advantage of this flaw to discover
private and sensitive information about another clients browsing
session." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.4.8-6+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid-purge", ver: "3.4.8-6+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3", ver: "3.4.8-6+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3-common", ver: "3.4.8-6+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3-dbg", ver: "3.4.8-6+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squidclient", ver: "3.4.8-6+deb8u4", rls: "DEB8" ) ) != NULL){
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

