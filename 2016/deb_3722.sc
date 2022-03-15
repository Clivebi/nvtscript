if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703722" );
	script_version( "2021-09-20T14:01:48+0000" );
	script_cve_id( "CVE-2016-1248" );
	script_name( "Debian Security Advisory DSA 3722-1 (vim - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-22 00:00:00 +0100 (Tue, 22 Nov 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3722.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "vim on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 2:7.4.488-7+deb8u1.

We recommend that you upgrade your vim packages." );
	script_tag( name: "summary", value: "Florian Larysch and Bram Moolenaar
discovered that vim, an enhanced vi editor, does not properly validate values
for the filetype, syntax and keymap options, which may result in the execution
of arbitrary code if a file with a specially crafted modeline is opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "vim", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-athena", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-common", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-dbg", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-doc", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-gnome", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-gtk", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-gui-common", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-lesstif", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-nox", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-runtime", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-tiny", ver: "2:7.4.488-7+deb8u1", rls: "DEB8" ) ) != NULL){
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
