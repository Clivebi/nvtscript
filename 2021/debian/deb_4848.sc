if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704848" );
	script_version( "2021-08-24T12:01:48+0000" );
	script_cve_id( "CVE-2020-15586", "CVE-2020-16845", "CVE-2020-7919", "CVE-2021-3114" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-24 12:01:48 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-02-10 04:00:29 +0000 (Wed, 10 Feb 2021)" );
	script_name( "Debian: Security Advisory for golang-1.11 (DSA-4848-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4848.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4848-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4848-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-1.11'
  package(s) announced via the DSA-4848-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in the implementation of the
Go programming language, which could result in denial of service and
the P-224 curve implementation could generate incorrect outputs." );
	script_tag( name: "affected", value: "'golang-1.11' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 1.11.6-1+deb10u4.

We recommend that you upgrade your golang-1.11 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "golang-1.11", ver: "1.11.6-1+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.11-doc", ver: "1.11.6-1+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.11-go", ver: "1.11.6-1+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.11-src", ver: "1.11.6-1+deb10u4", rls: "DEB10" ) )){
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

