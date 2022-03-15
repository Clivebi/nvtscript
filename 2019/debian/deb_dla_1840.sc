if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891840" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-11840" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-18 00:15:00 +0000 (Mon, 18 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-07-01 02:00:06 +0000 (Mon, 01 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for golang-go.crypto (DLA-1840-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/06/msg00029.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1840-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-go.crypto'
  package(s) announced via the DLA-1840-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in the amd64 implementation of salsa20. If more
than 256 GiB of keystream is generated, or if the counter otherwise
grows greater than 32 bits, the amd64 implementation will first generate
incorrect output, and then cycle back to previously generated keystream." );
	script_tag( name: "affected", value: "'golang-go.crypto' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.0~hg190-1+deb8u1.

obfs4proxy has been rebuilt as version 0.0.3-2+deb8u1.

We recommend that you upgrade your golang-golang-x-crypto-dev
and obfs4proxy packages, and rebuild any software using
golang-golang-x-crypto-dev." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "golang-go.crypto-dev", ver: "0.0~hg190-1+deb8u1", rls: "DEB8" ) )){
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

