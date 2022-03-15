if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892460" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-15586", "CVE-2020-16845", "CVE-2020-28367" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-16 03:15:00 +0000 (Wed, 16 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-22 04:00:12 +0000 (Sun, 22 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for golang-1.8 (DLA-2460-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00038.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2460-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-1.8'
  package(s) announced via the DLA-2460-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Three issues have been found in golang-1.8, a Go programming language
compiler version 1.8

CVE-2020-15586
Using the 100-continue in HTTP headers received by a net/http/Server
can lead to a data race involving the connection's buffered writer.

CVE-2020-16845
Certain invalid inputs to ReadUvarint or ReadVarint could cause those
functions to read an unlimited number of bytes from the ByteReader
argument before returning an error.

CVE-2020-28367
When using cgo, arbitrary code might be executed at build time." );
	script_tag( name: "affected", value: "'golang-1.8' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1.8.1-1+deb9u2.

We recommend that you upgrade your golang-1.8 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "golang-1.8", ver: "1.8.1-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.8-doc", ver: "1.8.1-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.8-go", ver: "1.8.1-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.8-src", ver: "1.8.1-1+deb9u2", rls: "DEB9" ) )){
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

