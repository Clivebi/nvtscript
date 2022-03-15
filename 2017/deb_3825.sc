if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703825" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_cve_id( "CVE-2016-3822" );
	script_name( "Debian Security Advisory DSA 3825-1 (jhead - security update)" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-31 00:00:00 +0200 (Fri, 31 Mar 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-05 20:33:00 +0000 (Mon, 05 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3825.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "jhead on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 1:2.97-1+deb8u1.

For the upcoming stable distribution (stretch), this problem has been
fixed in version 1:3.00-4.

For the unstable distribution (sid), this problem has been fixed in
version 1:3.00-4.

We recommend that you upgrade your jhead packages." );
	script_tag( name: "summary", value: "It was discovered that jhead, a tool to manipulate the non-image part of
EXIF compliant JPEG files, is prone to an out-of-bounds access
vulnerability, which may result in denial of service or, potentially,
the execution of arbitrary code if an image with specially crafted EXIF
data is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "jhead", ver: "1:3.00-4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "jhead", ver: "1:2.97-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

