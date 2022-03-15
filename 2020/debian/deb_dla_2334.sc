if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892334" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-7663" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-17 15:15:00 +0000 (Thu, 17 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-08-20 05:27:57 +0000 (Thu, 20 Aug 2020)" );
	script_name( "Debian LTS: Security Advisory for ruby-websocket-extensions (DLA-2334-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/08/msg00031.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2334-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/964274" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-websocket-extensions'
  package(s) announced via the DLA-2334-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a denial of service vulnerability
in ruby-websocket-extensions, a library for managing long-lived HTTP
'WebSocket' connections.

The parser took quadratic time when parsing a header containing an
unclosed string parameter value whose content is a repeating two-byte
sequence. This could be abused by an attacker to conduct a Regex
Denial Of Service (ReDoS) on a single-threaded server by providing a
malicious payload in the Sec-WebSocket-Extensions HTTP header." );
	script_tag( name: "affected", value: "'ruby-websocket-extensions' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
0.1.2-1+deb9u1.

We recommend that you upgrade your ruby-websocket-extensions packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-websocket-extensions", ver: "0.1.2-1+deb9u1", rls: "DEB9" ) )){
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

