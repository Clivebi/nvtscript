if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891030" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2017-11109" );
	script_name( "Debian LTS: Security Advisory for vim (DLA-1030-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-03 13:15:00 +0000 (Sat, 03 Aug 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/07/msg00023.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "vim on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2:7.3.547-7+deb7u4.

We recommend that you upgrade your vim packages." );
	script_tag( name: "summary", value: "Vim 8.0 allows attackers to cause a denial of service (invalid free) or
possibly have unspecified other impact via a crafted source (aka -S)
file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "vim", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-athena", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-common", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-dbg", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-doc", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-gnome", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-gtk", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-gui-common", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-lesstif", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-nox", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-runtime", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-tiny", ver: "2:7.3.547-7+deb7u4", rls: "DEB7" ) )){
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

