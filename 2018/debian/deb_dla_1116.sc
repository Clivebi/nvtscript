if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891116" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2017-14517", "CVE-2017-14519", "CVE-2017-14617" );
	script_name( "Debian LTS: Security Advisory for poppler (DLA-1116-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-27 17:22:00 +0000 (Wed, 27 Sep 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/09/msg00033.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "poppler on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.18.4-6+deb7u3.

We recommend that you upgrade your poppler packages." );
	script_tag( name: "summary", value: "It was discovered that poppler, a PDF rendering library, was affected
by several denial-of-service (application crash), null pointer
dereferences and memory corruption bugs:

CVE-2017-14517
NULL Pointer Dereference in the XRef::parseEntry() function in
XRef.cc

CVE-2017-14519
Memory corruption occurs in a call to Object::streamGetChar that
may lead to a denial of service or other unspecified impact.

CVE-2017-14617
Potential buffer overflow in the ImageStream class in Stream.cc,
which may lead to a denial of service or other unspecified impact." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-poppler-0.18", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-cpp-dev", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-cpp0", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-dev", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-glib-dev", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-glib8", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-private-dev", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt4-3", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt4-dev", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler19", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "poppler-dbg", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "poppler-utils", ver: "0.18.4-6+deb7u3", rls: "DEB7" ) )){
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

