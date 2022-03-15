if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891074" );
	script_version( "2020-01-29T08:22:52+0000" );
	script_cve_id( "CVE-2013-4473", "CVE-2013-4474", "CVE-2017-9775", "CVE-2017-9776", "CVE-2017-9865" );
	script_name( "Debian LTS: Security Advisory for poppler (DLA-1074-1)" );
	script_tag( name: "last_modification", value: "2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/08/msg00025.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "poppler on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.18.4-6+deb7u2.

We recommend that you upgrade your poppler packages." );
	script_tag( name: "summary", value: "Several buffer and integer overflow issues were discovered in Poppler,
a PDF library, that could lead to application crash or possibly other
unspecified impact via maliciously crafted files." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-poppler-0.18", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-cpp-dev", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-cpp0", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-dev", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-glib-dev", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-glib8", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-private-dev", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt4-3", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt4-dev", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler19", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "poppler-dbg", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "poppler-utils", ver: "0.18.4-6+deb7u2", rls: "DEB7" ) )){
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

