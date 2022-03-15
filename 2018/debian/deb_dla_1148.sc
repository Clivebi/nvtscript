if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891148" );
	script_version( "2021-06-21T02:00:27+0000" );
	script_cve_id( "CVE-2017-15041" );
	script_name( "Debian LTS: Security Advisory for golang (DLA-1148-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-19 20:11:00 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/10/msg00027.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "golang on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2:1.0.2-1.1+deb7u2.

We recommend that you upgrade your golang packages." );
	script_tag( name: "summary", value: "Go before 1.8.4 and 1.9.x before 1.9.1 allows 'go get' remote command
execution. Using custom domains, it is possible to arrange things so
that example.com/pkg1 points to a Subversion repository but
example.com/pkg1/pkg2 points to a Git repository. If the Subversion
repository includes a Git checkout in its pkg2 directory and some
other work is done to ensure the proper ordering of operations, 'go
get' can be tricked into reusing this Git checkout for the fetch of
code from pkg2. If the Subversion repository's Git checkout has
malicious commands in .git/hooks/, they will execute on the system
running 'go get.'" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "golang", ver: "2:1.0.2-1.1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-dbg", ver: "2:1.0.2-1.1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-doc", ver: "2:1.0.2-1.1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-go", ver: "2:1.0.2-1.1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-mode", ver: "2:1.0.2-1.1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-src", ver: "2:1.0.2-1.1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "kate-syntax-go", ver: "2:1.0.2-1.1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-syntax-go", ver: "2:1.0.2-1.1+deb7u2", rls: "DEB7" ) )){
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

