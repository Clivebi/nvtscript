if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892485" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2019-9512", "CVE-2019-9514" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-09 00:15:00 +0000 (Wed, 09 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-09 04:00:10 +0000 (Wed, 09 Dec 2020)" );
	script_name( "Debian LTS: Security Advisory for golang-golang-x-net-dev (DLA-2485-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/12/msg00011.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2485-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-golang-x-net-dev'
  package(s) announced via the DLA-2485-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The http2 server support in this package was vulnerable to
certain types of DOS attacks.

CVE-2019-9512

This code was vulnerable to ping floods, potentially leading to a denial of
service. The attacker sends continual pings to an HTTP/2 peer, causing the peer
to build an internal queue of responses. Depending on how efficiently this data
is queued, this can consume excess CPU, memory, or both.

CVE-2019-9514

This code was vulnerable to a reset flood, potentially leading to a denial
of service. The attacker opens a number of streams and sends an invalid request
over each stream that should solicit a stream of RST_STREAM frames from the
peer. Depending on how the peer queues the RST_STREAM frames, this can consume
excess memory, CPU, or both." );
	script_tag( name: "affected", value: "'golang-golang-x-net-dev' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1:0.0+git20161013.8b4af36+dfsg-3+deb9u1.

We recommend that you upgrade your golang-golang-x-net-dev packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "golang-go.net-dev", ver: "1:0.0+git20161013.8b4af36+dfsg-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-golang-x-net-dev", ver: "1:0.0+git20161013.8b4af36+dfsg-3+deb9u1", rls: "DEB9" ) )){
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

