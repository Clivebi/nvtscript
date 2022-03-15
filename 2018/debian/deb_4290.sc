if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704290" );
	script_version( "2021-06-16T13:21:12+0000" );
	script_cve_id( "CVE-2018-14346", "CVE-2018-14347", "CVE-2018-16430" );
	script_name( "Debian Security Advisory DSA 4290-1 (libextractor - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 13:21:12 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-10 00:00:00 +0200 (Mon, 10 Sep 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4290.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "libextractor on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1:1.3-4+deb9u2.

We recommend that you upgrade your libextractor packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/libextractor" );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in libextractor, a library to
extract arbitrary meta-data from files, which may lead to denial of
service or the execution of arbitrary code if a specially crafted file
is opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "extract", ver: "1:1.3-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libextractor-dbg", ver: "1:1.3-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libextractor-dev", ver: "1:1.3-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libextractor3", ver: "1:1.3-4+deb9u2", rls: "DEB9" ) )){
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

