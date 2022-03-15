if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891706" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2018-19058", "CVE-2018-20481", "CVE-2018-20662", "CVE-2019-7310", "CVE-2019-9200" );
	script_name( "Debian LTS: Security Advisory for poppler (DLA-1706-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-09 00:00:00 +0100 (Sat, 09 Mar 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-09 02:15:00 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00008.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "poppler on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.26.5-2+deb8u8.

We recommend that you upgrade your poppler packages." );
	script_tag( name: "summary", value: "Several security vulnerabilities were discovered in the poppler PDF
rendering shared library.

CVE-2018-19058

A reachable abort in Object.h will lead to denial-of-service because
EmbFile::save2 in FileSpec.cc lacks a stream check before saving an
embedded file.

CVE-2018-20481

Poppler mishandles unallocated XRef entries, which allows remote
attackers to cause a denial-of-service (NULL pointer dereference)
via a crafted PDF document.

CVE-2018-20662

Poppler allows attackers to cause a denial-of-service (application
crash and segmentation fault by crafting a PDF file in which an xref
data structure is corrupted.

CVE-2019-7310

A heap-based buffer over-read (due to an integer signedness error in
the XRef::getEntry function in XRef.cc) allows remote attackers to
cause a denial of service (application crash) or possibly have
unspecified other impact via a crafted PDF document.

CVE-2019-9200

A heap-based buffer underwrite exists in ImageStream::getLine()
located at Stream.cc that can (for example) be triggered by sending
a crafted PDF file to the pdfimages binary. It allows an attacker to
cause denial-of-service (segmentation fault) or possibly have
unspecified other impact." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-poppler-0.18", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-cpp-dev", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-cpp0", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-dev", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-glib-dev", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-glib-doc", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-glib8", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-private-dev", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt4-4", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt4-dev", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt5-1", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler-qt5-dev", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpoppler46", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "poppler-dbg", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "poppler-utils", ver: "0.26.5-2+deb8u8", rls: "DEB8" ) )){
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

