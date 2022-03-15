if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891581" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-19198", "CVE-2018-19199", "CVE-2018-19200" );
	script_name( "Debian LTS: Security Advisory for uriparser (DLA-1581-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-20 00:00:00 +0100 (Tue, 20 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/11/msg00019.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "uriparser on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.8.0.1-2+deb8u1.

We recommend that you upgrade your uriparser packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in uriparser, an Uniform Resource
Identifiers (URIs) parsing library.

CVE-2018-19198

UriQuery.c allows an out-of-bounds write via a uriComposeQuery* or
uriComposeQueryEx* function because the '&' character is mishandled in
certain contexts.

CVE-2018-19199

UriQuery.c allows an integer overflow via a uriComposeQuery* or
uriComposeQueryEx* function because of an unchecked multiplication.

CVE-2018-19200

UriCommon.c allows attempted operations on NULL input via a uriResetUri*
function." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "liburiparser-dev", ver: "0.8.0.1-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liburiparser1", ver: "0.8.0.1-2+deb8u1", rls: "DEB8" ) )){
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

