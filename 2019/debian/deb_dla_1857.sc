if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891857" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-11719", "CVE-2019-11729" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 18:15:00 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-07-21 02:00:11 +0000 (Sun, 21 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for nss (DLA-1857-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00017.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1857-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nss'
  package(s) announced via the DLA-1857-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Vulnerabilities have been discovered in nss, the Mozilla Network
Security Service library.

CVE-2019-11719: Out-of-bounds read when importing curve25519 private key

When importing a curve25519 private key in PKCS#8format with leading
0x00 bytes, it is possible to trigger an out-of-bounds read in the
Network Security Services (NSS) library. This could lead to
information disclosure.

CVE-2019-11729: Empty or malformed p256-ECDH public keys may trigger a
segmentation fault

Empty or malformed p256-ECDH public keys may trigger a segmentation
fault due values being improperly sanitized before being copied into
memory and used." );
	script_tag( name: "affected", value: "'nss' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2:3.26-1+debu8u5.

We recommend that you upgrade your nss packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libnss3", ver: "2:3.26-1+debu8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss3-1d", ver: "2:3.26-1+debu8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss3-dbg", ver: "2:3.26-1+debu8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss3-dev", ver: "2:3.26-1+debu8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss3-tools", ver: "2:3.26-1+debu8u5", rls: "DEB8" ) )){
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

