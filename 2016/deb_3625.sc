if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703625" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556" );
	script_name( "Debian Security Advisory DSA 3625-1 (squid3 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-08-02 10:57:49 +0530 (Tue, 02 Aug 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3625.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "squid3 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these
problems have been fixed in version 3.4.8-6+deb8u3.

For the testing (stretch) and unstable (sid) distributions, these
problems have been fixed in version 3.5.19-1.

We recommend that you upgrade your squid3 packages." );
	script_tag( name: "summary", value: "Several security issues have been discovered
in the Squid caching proxy.

CVE-2016-4051:

CESG and Yuriy M. Kaminskiy discovered that Squid cachemgr.cgi was
vulnerable to a buffer overflow when processing remotely supplied
inputs relayed through Squid.

CVE-2016-4052:

CESG discovered that a buffer overflow made Squid vulnerable to a
Denial of Service (DoS) attack when processing ESI responses.

CVE-2016-4053:

CESG found that Squid was vulnerable to public information
disclosure of the server stack layout when processing ESI responses.

CVE-2016-4054:

CESG discovered that Squid was vulnerable to remote code execution
when processing ESI responses.

CVE-2016-4554:

Jianjun Chen found that Squid was vulnerable to a header smuggling
attack that could lead to cache poisoning and to bypass of
same-origin security policy in Squid and some client browsers.

CVE-2016-4555,
CVE-2016-4556:

'bfek-18' and '@vftable' found that Squid was vulnerable to a Denial
of Service (DoS) attack when processing ESI responses, due to
incorrect pointer handling and reference counting." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.4.8-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid-purge", ver: "3.4.8-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3", ver: "3.4.8-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3-common", ver: "3.4.8-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3-dbg", ver: "3.4.8-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squidclient", ver: "3.4.8-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid", ver: "3.5.19-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.5.19-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid-common", ver: "3.5.19-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid-dbg", ver: "3.5.19-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid-purge", ver: "3.5.19-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squid3", ver: "3.5.19-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squidclient", ver: "3.5.19-1", rls: "DEB9" ) ) != NULL){
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

