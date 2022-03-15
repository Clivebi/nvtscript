if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891620" );
	script_version( "2021-06-21T02:00:27+0000" );
	script_cve_id( "CVE-2018-19134", "CVE-2018-19478" );
	script_name( "Debian LTS: Security Advisory for ghostscript (DLA-1620-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-12-28 00:00:00 +0100 (Fri, 28 Dec 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-11 15:54:00 +0000 (Fri, 11 Jan 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/12/msg00019.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "ghostscript on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
9.06~dfsg-2+deb8u13.

We recommend that you upgrade your ghostscript packages." );
	script_tag( name: "summary", value: "Some vulnerabilities were discovered in ghostscript, an interpreter for the
PostScript language and for PDF.

CVE-2018-19134

The setpattern operator did not properly validate certain types. A specially
crafted PostScript document could exploit this to crash Ghostscript or,
possibly, execute arbitrary code in the context of the Ghostscript process.
This is a type confusion issue because of failure to check whether the
Implementation of a pattern dictionary was a structure type.

CVE-2018-19478

Attempting to open a carefully crafted PDF file results in long-running
computation. A sufficiently bad page tree can lead to us taking significant
amounts of time when checking the tree for recursion." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ghostscript", ver: "9.06~dfsg-2+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-dbg", ver: "9.06~dfsg-2+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-doc", ver: "9.06~dfsg-2+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.06~dfsg-2+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs-dev", ver: "9.06~dfsg-2+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9", ver: "9.06~dfsg-2+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.06~dfsg-2+deb8u13", rls: "DEB8" ) )){
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

