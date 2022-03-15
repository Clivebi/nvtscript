if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703691" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2013-5653", "CVE-2016-7976", "CVE-2016-7977", "CVE-2016-7978", "CVE-2016-7979", "CVE-2016-8602" );
	script_name( "Debian Security Advisory DSA 3691-1 (ghostscript - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-10-12 00:00:00 +0200 (Wed, 12 Oct 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3691.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "ghostscript on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 9.06~dfsg-2+deb8u3.

We recommend that you upgrade your ghostscript packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in Ghostscript, the GPL PostScript/PDF interpreter, which may lead to the execution
of arbitrary code or information disclosure if a specially crafted Postscript file
is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ghostscript", ver: "9.06~dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-dbg", ver: "9.06~dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-doc", ver: "9.06~dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.06~dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs-dev", ver: "9.06~dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs9", ver: "9.06~dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.06~dfsg-2+deb8u3", rls: "DEB8" ) ) != NULL){
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

