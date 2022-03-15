if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892110" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2014-0193", "CVE-2014-3488", "CVE-2019-16869", "CVE-2019-20444", "CVE-2019-20445", "CVE-2020-7238" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-26 10:15:00 +0000 (Mon, 26 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-02-20 04:00:10 +0000 (Thu, 20 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for netty-3.9 (DLA-2110-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2110-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/746639" );
	script_xref( name: "URL", value: "https://bugs.debian.org/941266" );
	script_xref( name: "URL", value: "https://bugs.debian.org/950966" );
	script_xref( name: "URL", value: "https://bugs.debian.org/950967" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'netty-3.9'
  package(s) announced via the DLA-2110-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in Netty, a Java NIO
client/server socket framework:

CVE-2014-0193

WebSocket08FrameDecoder allows remote attackers to cause a denial
of service (memory consumption) via a TextWebSocketFrame followed
by a long stream of ContinuationWebSocketFrames.

CVE-2014-3488

The SslHandler allows remote attackers to cause a denial of
service (infinite loop and CPU consumption) via a crafted
SSLv2Hello message.

CVE-2019-16869

Netty mishandles whitespace before the colon in HTTP headers (such
as a 'Transfer-Encoding : chunked' line), which leads to HTTP
request smuggling.

CVE-2019-20444

HttpObjectDecoder.java allows an HTTP header that lacks a colon,
which might be interpreted as a separate header with an incorrect
syntax, or might be interpreted as an 'invalid fold.'

CVE-2019-20445

HttpObjectDecoder.java allows a Content-Length header to be
accompanied by a second Content-Length header, or by a
Transfer-Encoding header.

CVE-2020-7238

Netty allows HTTP Request Smuggling because it mishandles
Transfer-Encoding whitespace (such as a
[space]Transfer-Encoding:chunked line) and a later Content-Length
header." );
	script_tag( name: "affected", value: "'netty-3.9' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.9.0.Final-1+deb8u1.

We recommend that you upgrade your netty-3.9 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libnetty-3.9-java", ver: "3.9.0.Final-1+deb8u1", rls: "DEB8" ) )){
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

