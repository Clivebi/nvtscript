if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703984" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_cve_id( "CVE-2017-14867" );
	script_name( "Debian Security Advisory DSA 3984-1 (git - security update)" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-26 00:00:00 +0200 (Tue, 26 Sep 2017)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-26 14:55:00 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3984.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "git on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1:2.1.4-2.1+deb8u5.

For the stable distribution (stretch), this problem has been fixed in
version 1:2.11.0-3+deb9u2.

For the unstable distribution (sid), this problem has been fixed in
version 1:2.14.2-1.

We recommend that you upgrade your git packages." );
	script_tag( name: "summary", value: "joernchen discovered that the git-cvsserver subcommand of Git, a
distributed version control system, suffers from a shell command
injection vulnerability due to unsafe use of the Perl backtick
operator. The git-cvsserver subcommand is reachable from the
git-shell subcommand even if CVS support has not been configured
(however, the git-cvs package needs to be installed).

In addition to fixing the actual bug, this update removes the
cvsserver subcommand from git-shell by default. Refer to the updated
documentation for instructions how to re-enable in case this CVS
functionality is still needed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "git", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-all", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-arch", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-core", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-cvs", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-daemon-run", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-daemon-sysvinit", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-doc", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-el", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-email", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-gui", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-man", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-mediawiki", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-svn", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gitk", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gitweb", ver: "1:2.11.0-3+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-all", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-arch", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-core", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-cvs", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-daemon-run", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-daemon-sysvinit", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-doc", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-el", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-email", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-gui", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-man", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-mediawiki", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-svn", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gitk", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gitweb", ver: "1:2.1.4-2.1+deb8u5", rls: "DEB8" ) ) != NULL){
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

