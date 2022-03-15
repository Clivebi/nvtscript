if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891749" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2019-9741" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-22 13:05:00 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "creation_date", value: "2019-04-03 20:00:00 +0000 (Wed, 03 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for golang (DLA-1749-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1749-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/924630" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang'
  package(s) announced via the DLA-1749-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a CRLF injection attack in the Go
programming language runtime library.

Passing \\r\\n to http.NewRequest could allow execution of arbitrary
HTTP headers or Redis commands." );
	script_tag( name: "affected", value: "'golang' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in golang version
2:1.3.3-1+deb8u2.

We recommend that you upgrade your golang packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "golang", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-doc", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-darwin-386", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-darwin-amd64", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-freebsd-386", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-freebsd-amd64", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-freebsd-arm", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-linux-386", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-linux-amd64", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-linux-arm", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-netbsd-386", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-netbsd-amd64", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-windows-386", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go-windows-amd64", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-mode", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-src", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "kate-syntax-go", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-syntax-go", ver: "2:1.3.3-1+deb8u2", rls: "DEB8" ) )){
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

