if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892520" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2020-27813" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 14:44:00 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-01-11 13:00:59 +0000 (Mon, 11 Jan 2021)" );
	script_name( "Debian LTS: Security Advisory for golang-websocket (DLA-2520-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/01/msg00008.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2520-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-websocket'
  package(s) announced via the DLA-2520-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "There was an integer overflow vulnerability concerning the length of websocket
frames received via a websocket connection. An attacker could use this flaw to
cause a denial of service attack on an HTTP Server allowing websocket
connections." );
	script_tag( name: "affected", value: "'golang-websocket' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.1.0-1+deb9u1.

We recommend that you upgrade your golang-websocket packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "golang-github-gorilla-websocket-dev", ver: "1.1.0-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-websocket-dev", ver: "1.1.0-1+deb9u1", rls: "DEB9" ) )){
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

