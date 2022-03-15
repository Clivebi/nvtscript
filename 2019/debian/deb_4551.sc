if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704551" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-17596" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-22 16:01:00 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "creation_date", value: "2019-10-27 03:00:16 +0000 (Sun, 27 Oct 2019)" );
	script_name( "Debian Security Advisory DSA 4551-1 (golang-1.11 - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4551.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4551-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-1.11'
  package(s) announced via the DSA-4551-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Daniel Mandragona discovered that invalid DSA public keys can cause a
panic in dsa.Verify(), resulting in denial of service." );
	script_tag( name: "affected", value: "'golang-1.11' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.11.6-1+deb10u3.

We recommend that you upgrade your golang-1.11 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "golang-1.11", ver: "1.11.6-1+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.11-doc", ver: "1.11.6-1+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.11-go", ver: "1.11.6-1+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.11-src", ver: "1.11.6-1+deb10u3", rls: "DEB10" ) )){
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

