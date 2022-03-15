if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891552" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2018-17961", "CVE-2018-18073", "CVE-2018-18284" );
	script_name( "Debian LTS: Security Advisory for ghostscript (DLA-1552-1)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-23 00:00:00 +0200 (Tue, 23 Oct 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/10/msg00013.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "ghostscript on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
9.06~dfsg-2+deb8u11.

We recommend that you upgrade your ghostscript packages." );
	script_tag( name: "summary", value: "This is a follow-up update for the recently discovered -dSAFER issues
reported by Tavis Ormandy.

Tavis Ormandy discovered multiple vulnerabilities in Ghostscript, an
interpreter for the PostScript language, which could result in denial of
service, the creation of files or the execution of arbitrary code if a
malformed Postscript file is processed (despite the dSAFER sandbox being
enabled)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ghostscript", ver: "9.06~dfsg-2+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-dbg", ver: "9.06~dfsg-2+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-doc", ver: "9.06~dfsg-2+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.06~dfsg-2+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs-dev", ver: "9.06~dfsg-2+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9", ver: "9.06~dfsg-2+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.06~dfsg-2+deb8u11", rls: "DEB8" ) )){
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

