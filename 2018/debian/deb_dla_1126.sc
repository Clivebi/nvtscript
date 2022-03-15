if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891126" );
	script_version( "2021-06-16T02:00:28+0000" );
	script_cve_id( "CVE-2017-13720", "CVE-2017-13722" );
	script_name( "Debian LTS: Security Advisory for libxfont (DLA-1126-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:00:28 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-13 02:29:00 +0000 (Mon, 13 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/10/msg00006.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libxfont on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', this issue has been fixed in libxfont version
1:1.4.5-5+deb7u1.

We recommend that you upgrade your libxfont packages." );
	script_tag( name: "summary", value: "It was discovered that there two vulnerabilities the library providing
font selection and rasterisation, libxfont:

  * CVE-2017-13720: If a pattern contained a '?' character any character
in the string is skipped even if it was a '\\0'. The rest of the
matching then read invalid memory.

  * CVE-2017-13722: A malformed PCF file could cause the library to make
reads from random heap memory that was behind the `strings` buffer,
leading to an application crash or an information leak." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxfont-dev", ver: "1:1.4.5-5+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxfont1", ver: "1:1.4.5-5+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxfont1-dbg", ver: "1:1.4.5-5+deb7u1", rls: "DEB7" ) )){
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

