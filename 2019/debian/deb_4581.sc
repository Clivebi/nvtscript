if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704581" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1387", "CVE-2019-19604" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-28 01:15:00 +0000 (Tue, 28 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-12-11 03:00:08 +0000 (Wed, 11 Dec 2019)" );
	script_name( "Debian Security Advisory DSA 4581-1 (git - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4581.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4581-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'git'
  package(s) announced via the DSA-4581-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in git, a fast, scalable,
distributed revision control system.

CVE-2019-1348
It was reported that the --export-marks option of git fast-import is
exposed also via the in-stream command feature export-marks=...,
allowing to overwrite arbitrary paths.

CVE-2019-1387
It was discovered that submodule names are not validated strictly
enough, allowing very targeted attacks via remote code execution
when performing recursive clones.

CVE-2019-19604
Joern Schneeweisz reported a vulnerability, where a recursive clone
followed by a submodule update could execute code contained within
the repository without the user explicitly having asked for that. It
is now disallowed for `.gitmodules` to have entries that set
`submodule..update=!command`.

In addition this update addresses a number of security issues which are
only an issue if git is operating on an NTFS filesystem (CVE-2019-1349,
CVE-2019-1352 and CVE-2019-1353
)." );
	script_tag( name: "affected", value: "'git' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 1:2.11.0-3+deb9u5.

For the stable distribution (buster), these problems have been fixed in
version 1:2.20.1-2+deb10u1.

We recommend that you upgrade your git packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "git", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-all", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-cvs", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-daemon-run", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-daemon-sysvinit", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-doc", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-el", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-email", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-gui", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-man", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-mediawiki", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-svn", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gitk", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gitweb", ver: "1:2.20.1-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-all", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-arch", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-core", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-cvs", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-daemon-run", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-daemon-sysvinit", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-doc", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-el", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-email", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-gui", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-man", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-mediawiki", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-svn", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gitk", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gitweb", ver: "1:2.11.0-3+deb9u5", rls: "DEB9" ) )){
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

