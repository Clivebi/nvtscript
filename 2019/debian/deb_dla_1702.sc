if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891702" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2018-1056", "CVE-2019-9210" );
	script_name( "Debian LTS: Security Advisory for advancecomp (DLA-1702-1)" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-04 00:00:00 +0100 (Mon, 04 Mar 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00004.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "advancecomp on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.19-1+deb8u1.

We recommend that you upgrade your advancecomp packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in advancecomp, a collection
of recompression utilities.

CVE-2018-1056

Joonun Jang discovered that the advzip tool was prone to a
heap-based buffer overflow. This might allow an attacker to cause a
denial-of-service (application crash) or other unspecified impact
via a crafted file.

CVE-2019-9210

The png_compress function in pngex.cc in advpng has an integer
overflow upon encountering an invalid PNG size, which results in
another heap based buffer overflow." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "advancecomp", ver: "1.19-1+deb8u1", rls: "DEB8" ) )){
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
