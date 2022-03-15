if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844361" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2019-20503", "CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6808", "CVE-2020-6810", "CVE-2020-6812", "CVE-2020-6813", "CVE-2020-6814", "CVE-2020-6815", "CVE-2020-6809", "CVE-2020-6811" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-22 20:15:00 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-03-12 04:00:13 +0000 (Thu, 12 Mar 2020)" );
	script_name( "Ubuntu: Security Advisory for firefox (USN-4299-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4299-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-March/005355.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the USN-4299-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, spoof the URL or
other browser chrome, obtain sensitive information, bypass Content
Security Policy (CSP) protections, or execute arbitrary code.
(CVE-2019-20503, CVE-2020-6805, CVE-2020-6806, CVE-2020-6807,
CVE-2020-6808, CVE-2020-6810, CVE-2020-6812, CVE-2020-6813, CVE-2020-6814,
CVE-2020-6815)

It was discovered that Web Extensions with the all-url permission could
access local files. If a user were tricked in to installing a specially
crafted extension, an attacker could potentially exploit this to obtain
sensitive information. (CVE-2020-6809)

It was discovered that the Devtools' 'Copy as cURL' feature did not fully
escape website-controlled data. If a user were tricked in to using the
'Copy as cURL' feature to copy and paste a command with specially crafted
data in to a terminal, an attacker could potentially exploit this to
execute arbitrary commands via command injection. (CVE-2020-6811)" );
	script_tag( name: "affected", value: "'firefox' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "firefox", ver: "74.0+build3-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "firefox", ver: "74.0+build3-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "firefox", ver: "74.0+build3-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
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

