if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703521" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-2315", "CVE-2016-2324" );
	script_name( "Debian Security Advisory DSA 3521-1 (git - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-19 00:00:00 +0100 (Sat, 19 Mar 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3521.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|7)" );
	script_tag( name: "affected", value: "git on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1:1.7.10.4-1+wheezy3.

For the stable distribution (jessie), these problems have been fixed in
version 1:2.1.4-2.1+deb8u2.

For the unstable distribution (sid), these problems have been fixed in
version 1:2.8.0~rc3-1.
CVE-2016-2315

was already fixed in version 1:2.7.0-1.

We recommend that you upgrade your git packages." );
	script_tag( name: "summary", value: "Lael Cellier discovered two buffer
overflow vulnerabilities in git, a fast, scalable, distributed revision control
system, which could be exploited for remote execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "git", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-all", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-arch", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-core", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-cvs", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-daemon-run", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-daemon-sysvinit", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-doc", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-el", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-email", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-gui", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-man", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-mediawiki", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-svn", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gitk", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gitweb", ver: "1:2.1.4-2.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-all", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-arch", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-core", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-cvs", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-daemon-run", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-daemon-sysvinit", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-doc", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-el", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-email", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-gui", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-man", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "git-svn", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gitk", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gitweb", ver: "1:1.7.10.4-1+wheezy3", rls: "DEB7" ) ) != NULL){
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

