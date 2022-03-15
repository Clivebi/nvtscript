if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891858" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-12525", "CVE-2019-12529" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-11 00:15:00 +0000 (Sat, 11 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-07-21 02:00:14 +0000 (Sun, 21 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for squid3 (DLA-1858-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1858-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid3'
  package(s) announced via the DLA-1858-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Squid, a high-performance proxy caching server for web clients, has been
found vulnerable to denial of service attacks associated with HTTP
authentication header processing.

CVE-2019-12525

Due to incorrect buffer management Squid is vulnerable to a denial
of service attack when processing HTTP Digest Authentication
credentials.

Due to incorrect input validation the HTTP Request header parser for
Digest authentication may access memory outside the allocated memory
buffer.

On systems with memory access protections this can result in the
Squid process being terminated unexpectedly. Resulting in a denial
of service for all clients using the proxy.

CVE-2019-12529

Due to incorrect buffer management Squid is vulnerable to a denial
of service attack when processing HTTP Basic Authentication
credentials.

Due to incorrect string termination the Basic authentication
credentials decoder may access memory outside the decode buffer.

On systems with memory access protections this can result in the
Squid process being terminated unexpectedly. Resulting in a denial
of service for all clients using the proxy." );
	script_tag( name: "affected", value: "'squid3' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.4.8-6+deb8u8.

We recommend that you upgrade your squid3 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "squid-cgi", ver: "3.4.8-6+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid-purge", ver: "3.4.8-6+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid3", ver: "3.4.8-6+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid3-common", ver: "3.4.8-6+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid3-dbg", ver: "3.4.8-6+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squidclient", ver: "3.4.8-6+deb8u8", rls: "DEB8" ) )){
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
exit( 0 );

