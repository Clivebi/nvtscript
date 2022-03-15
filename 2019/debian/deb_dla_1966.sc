if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891966" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-17544" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-19 21:15:00 +0000 (Sat, 19 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-10-20 02:00:09 +0000 (Sun, 20 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for aspell (DLA-1966-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00027.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1966-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aspell'
  package(s) announced via the DLA-1966-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Aspell, the GNU spell checker, incorrectly
handled certain inputs which leads to a stack-based buffer over-read.
An attacker could potentially access sensitive information." );
	script_tag( name: "affected", value: "'aspell' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.60.7~20110707-1.3+deb8u1.

We recommend that you upgrade your aspell packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "aspell", ver: "0.60.7~20110707-1.3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "aspell-doc", ver: "0.60.7~20110707-1.3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libaspell-dev", ver: "0.60.7~20110707-1.3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libaspell15", ver: "0.60.7~20110707-1.3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpspell-dev", ver: "0.60.7~20110707-1.3+deb8u1", rls: "DEB8" ) )){
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

