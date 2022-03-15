if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891951" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-17362" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-09 19:15:00 +0000 (Sat, 09 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-10-10 02:00:11 +0000 (Thu, 10 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for libtomcrypt (DLA-1951-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00010.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1951-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtomcrypt'
  package(s) announced via the DLA-1951-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a denial of service vulnerability
in the libtomcrypt cryptographic library.

An out-of-bounds read and crash could occur via carefully-crafted
'DER' encoded data (eg. by importing an X.509 certificate)." );
	script_tag( name: "affected", value: "'libtomcrypt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in libtomcrypt version
1.17-6+deb8u1.

We recommend that you upgrade your libtomcrypt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtomcrypt-dev", ver: "1.17-6+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcrypt0", ver: "1.17-6+deb8u1", rls: "DEB8" ) )){
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

