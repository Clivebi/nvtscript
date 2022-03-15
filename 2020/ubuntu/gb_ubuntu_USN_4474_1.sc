if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844550" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_cve_id( "CVE-2020-15664", "CVE-2020-15665", "CVE-2020-15666", "CVE-2020-15670", "CVE-2020-12400", "CVE-2020-12401", "CVE-2020-6829", "CVE-2020-15668" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-02 19:35:00 +0000 (Fri, 02 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-02 11:52:14 +0530 (Wed, 02 Sep 2020)" );
	script_name( "Ubuntu: Security Advisory for firefox (USN-4474-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "USN", value: "4474-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-August/005578.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the USN-4474-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, trick the user
in to installing a malicious extension, spoof the URL bar, leak sensitive
information between origins, or execute arbitrary code. (CVE-2020-15664,
CVE-2020-15665, CVE-2020-15666, CVE-2020-15670)

It was discovered that NSS incorrectly handled certain signatures.
An attacker could possibly use this issue to expose sensitive information.
(CVE-2020-12400, CVE-2020-12401, CVE-2020-6829)

A data race was discovered when importing certificate information in to
the trust store. An attacker could potentially exploit this to cause an
unspecified impact. (CVE-2020-15668)" );
	script_tag( name: "affected", value: "'firefox' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "firefox", ver: "80.0+build2-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
}
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "firefox", ver: "80.0+build2-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
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
}
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "firefox", ver: "80.0+build2-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
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
}
exit( 0 );

