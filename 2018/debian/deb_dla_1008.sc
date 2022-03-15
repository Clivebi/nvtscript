if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891008" );
	script_version( "2021-06-21T02:00:27+0000" );
	script_cve_id( "CVE-2017-7375", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050" );
	script_name( "Debian LTS: Security Advisory for libxml2 (DLA-1008-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-18 14:17:00 +0000 (Sun, 18 Mar 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/06/msg00037.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libxml2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2.8.0+dfsg1-7+wheezy8.

We recommend that you upgrade your libxml2 packages." );
	script_tag( name: "summary", value: "CVE-2017-7375
Missing validation for external entities in xmlParsePEReference

CVE-2017-9047
CVE-2017-9048
A buffer overflow was discovered in libxml2 20904-GITv2.9.4-16-g0741801.
The function xmlSnprintfElementContent in valid.c is supposed to
recursively dump the element content definition into a char buffer 'buf'
of size 'size'. The variable len is assigned strlen(buf).
If the content->type is XML_ELEMENT_CONTENT_ELEMENT, then (i) the
content->prefix is appended to buf (if it actually fits) whereupon
(ii) content->name is written to the buffer. However, the check for
whether the content->name actually fits also uses 'len' rather than
the updated buffer length strlen(buf). This allows us to write about
'size' many bytes beyond the allocated memory. This vulnerability
causes programs that use libxml2, such as PHP, to crash.

CVE-2017-9049
CVE-2017-9050
libxml2 20904-GITv2.9.4-16-g0741801 is vulnerable to a heap-based
buffer over-read in the xmlDictComputeFastKey function in dict.c.
This vulnerability causes programs that use libxml2, such as PHP,
to crash. This vulnerability exists because of an incomplete fix
for libxml2 Bug 759398." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxml2", ver: "2.8.0+dfsg1-7+wheezy8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.8.0+dfsg1-7+wheezy8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.8.0+dfsg1-7+wheezy8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.8.0+dfsg1-7+wheezy8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.8.0+dfsg1-7+wheezy8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-utils-dbg", ver: "2.8.0+dfsg1-7+wheezy8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.8.0+dfsg1-7+wheezy8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.8.0+dfsg1-7+wheezy8", rls: "DEB7" ) )){
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

