if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891916" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2018-16391", "CVE-2018-16392", "CVE-2018-16393", "CVE-2018-16418", "CVE-2018-16419", "CVE-2018-16420", "CVE-2018-16421", "CVE-2018-16422", "CVE-2018-16423", "CVE-2018-16424", "CVE-2018-16425", "CVE-2018-16426", "CVE-2018-16427", "CVE-2019-15945", "CVE-2019-15946" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-09-12 02:00:33 +0000 (Thu, 12 Sep 2019)" );
	script_name( "Debian LTS: Security Advisory for opensc (DLA-1916-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/09/msg00009.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1916-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/909444" );
	script_xref( name: "URL", value: "https://bugs.debian.org/939668" );
	script_xref( name: "URL", value: "https://bugs.debian.org/939669" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'opensc'
  package(s) announced via the DLA-1916-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security vulnerabilities were fixed in opensc, a set of
libraries and utilities to access smart cards that support
cryptographic operations.

Out-of-bounds reads, buffer overflows and double frees could be used
by attackers able to supply crafted smart cards to cause a denial of
service (application crash) or possibly have unspecified other impact." );
	script_tag( name: "affected", value: "'opensc' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.16.0-3+deb8u1.

We recommend that you upgrade your opensc packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "opensc", ver: "0.16.0-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "opensc-pkcs11", ver: "0.16.0-3+deb8u1", rls: "DEB8" ) )){
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
exit( 0 );

