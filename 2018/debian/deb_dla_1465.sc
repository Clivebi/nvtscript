if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891465" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2017-12081", "CVE-2017-12082", "CVE-2017-12086", "CVE-2017-12099", "CVE-2017-12100", "CVE-2017-12101", "CVE-2017-12102", "CVE-2017-12103", "CVE-2017-12104", "CVE-2017-12105", "CVE-2017-2899", "CVE-2017-2900", "CVE-2017-2901", "CVE-2017-2902", "CVE-2017-2903", "CVE-2017-2904", "CVE-2017-2905", "CVE-2017-2906", "CVE-2017-2907", "CVE-2017-2908", "CVE-2017-2918" );
	script_name( "Debian LTS: Security Advisory for blender (DLA-1465-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-14 00:00:00 +0200 (Tue, 14 Aug 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-26 19:24:00 +0000 (Tue, 26 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00011.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "blender on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.72.b+dfsg0-3+deb8u1.

We recommend that you upgrade your blender packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in various parsers of
Blender, a 3D modeller/ renderer. Malformed .blend model files and
malformed multimedia files (AVI, BMP, HDR, CIN, IRIS, PNG, TIFF) may
result in the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "blender", ver: "2.72.b+dfsg0-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "blender-data", ver: "2.72.b+dfsg0-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "blender-dbg", ver: "2.72.b+dfsg0-3+deb8u1", rls: "DEB8" ) )){
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

