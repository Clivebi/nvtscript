if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844239" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2018-14498", "CVE-2018-19664", "CVE-2018-20330", "CVE-2019-2201" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-19 01:15:00 +0000 (Tue, 19 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-11-14 03:01:54 +0000 (Thu, 14 Nov 2019)" );
	script_name( "Ubuntu Update for libjpeg-turbo USN-4190-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4190-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-November/005203.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libjpeg-turbo'
  package(s) announced via the USN-4190-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libjpeg-turbo incorrectly handled certain BMP images.
An attacker could possibly use this issue to expose sensitive information.
This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2018-14498)

It was discovered that libjpeg-turbo incorrectly handled certain JPEG images.
An attacker could possibly use this issue to expose sensitive information.
This issue only affected Ubuntu 19.04. (CVE-2018-19664)

It was discovered that libjpeg-turbo incorrectly handled certain BMP images.
An attacker could possibly use this issue to execute arbitrary code. This
issue only affected Ubuntu 19.04. (CVE-2018-20330)

It was discovered that libjpeg-turbo incorrectly handled certain JPEG images.
An attacker could possibly cause a denial of service or execute arbitrary code.
(CVE-2019-2201)" );
	script_tag( name: "affected", value: "'libjpeg-turbo' package(s) on Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libjpeg-turbo8", ver: "1.5.2-0ubuntu5.18.04.3", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "libjpeg-turbo8", ver: "2.0.1-0ubuntu2.2", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libjpeg-turbo8", ver: "1.4.2-0ubuntu3.3", rls: "UBUNTU16.04 LTS" ) )){
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

