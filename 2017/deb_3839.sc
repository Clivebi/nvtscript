if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703839" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_cve_id( "CVE-2016-10244", "CVE-2017-8105", "CVE-2017-8287" );
	script_name( "Debian Security Advisory DSA 3839-1 (freetype - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-28 00:00:00 +0200 (Fri, 28 Apr 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-26 12:33:00 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3839.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "freetype on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 2.5.2-3+deb8u2.

We recommend that you upgrade your freetype packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in Freetype. Opening malformed
fonts may result in denial of service or the execution of arbitrary
code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "freetype2-demos", ver: "2.5.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6:amd64", ver: "2.5.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6:i386", ver: "2.5.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreetype6-dev", ver: "2.5.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
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

