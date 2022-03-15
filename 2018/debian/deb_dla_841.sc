if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890841" );
	script_version( "2020-01-29T08:28:43+0000" );
	script_cve_id( "CVE-2015-0253", "CVE-2016-8743" );
	script_name( "Debian LTS: Security Advisory for apache2 (DLA-841-2)" );
	script_tag( name: "last_modification", value: "2020-01-29 08:28:43 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/07/msg00038.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "apache2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these
problems have been fixed in version 2.2.22-13+deb7u11.

We recommend that you upgrade your apache2 packages." );
	script_tag( name: "summary", value: "The fix for CVE-2016-8743 introduced a regression which would segfault
apache workers under certain conditions (#858373), an issue similar to
previously fixed CVE-2015-0253.

The issue was introduced in DLA-841-1 and the associated
2.2.22-13+deb7u8 package version." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "apache2", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-dbg", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-doc", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-mpm-event", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-mpm-itk", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-mpm-prefork", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-mpm-worker", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-prefork-dev", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-suexec", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-suexec-custom", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-threaded-dev", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-utils", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2.2-bin", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2.2-common", ver: "2.2.22-13+deb7u11", rls: "DEB7" ) )){
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

