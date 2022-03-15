if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703838" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_cve_id( "CVE-2016-10219", "CVE-2016-10220", "CVE-2017-5951", "CVE-2017-7207", "CVE-2017-8291" );
	script_name( "Debian Security Advisory DSA 3838-1 (ghostscript - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-28 00:00:00 +0200 (Fri, 28 Apr 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3838.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "ghostscript on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 9.06~dfsg-2+deb8u5.

For the unstable distribution (sid), these problems have been fixed in
version 9.20~dfsg-3.1 or earlier versions.

We recommend that you upgrade your ghostscript packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in Ghostscript, the GPL
PostScript/PDF interpreter, which may lead to the execution of arbitrary
code or denial of service if a specially crafted Postscript file is
processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ghostscript", ver: "9.06~dfsg-2+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-dbg", ver: "9.06~dfsg-2+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-doc", ver: "9.06~dfsg-2+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.06~dfsg-2+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs-dev", ver: "9.06~dfsg-2+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs9", ver: "9.06~dfsg-2+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.06~dfsg-2+deb8u5", rls: "DEB8" ) ) != NULL){
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

