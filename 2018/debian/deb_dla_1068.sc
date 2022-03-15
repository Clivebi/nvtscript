if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891068" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2017-1000117" );
	script_name( "Debian LTS: Security Advisory for git (DLA-1068-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/08/msg00020.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "git on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1:1.7.10.4-1+wheezy5.

We recommend that you upgrade your git packages." );
	script_tag( name: "summary", value: "Joern Schneeweisz discovered that git, a distributed revision control
system, did not correctly handle maliciously constructed ssh://
URLs. This allowed an attacker to run an arbitrary shell command, for
instance via git submodules." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "git", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-all", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-arch", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-core", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-cvs", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-daemon-run", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-daemon-sysvinit", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-doc", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-el", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-email", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-gui", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-man", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-svn", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gitk", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gitweb", ver: "1:1.7.10.4-1+wheezy5", rls: "DEB7" ) )){
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

