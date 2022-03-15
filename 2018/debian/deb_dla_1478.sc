if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891478" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2018-14346", "CVE-2018-14347" );
	script_name( "Debian LTS: Security Advisory for libextractor (DLA-1478-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-26 00:00:00 +0200 (Sun, 26 Aug 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00025.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libextractor on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these issues have been fixed in libextractor
version 1:1.3-2+deb8u2.

We recommend that you upgrade your libextractor packages." );
	script_tag( name: "summary", value: "It was discovered that there were two vulnerabilities in libextractor,
a library to obtain metadata from files of arbitrary type.

  * A stack-based buffer overflow in unzip.c. (CVE-2018-14346)

  * An infinite loop vulnerability in mpeg_extractor.c. (CVE-2018-14347)" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "extract", ver: "1:1.3-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libextractor-dbg", ver: "1:1.3-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libextractor-dev", ver: "1:1.3-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libextractor3", ver: "1:1.3-2+deb8u2", rls: "DEB8" ) )){
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

