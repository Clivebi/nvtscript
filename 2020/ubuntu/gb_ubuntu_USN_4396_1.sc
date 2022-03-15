if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844472" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_cve_id( "CVE-2020-0093", "CVE-2020-0182", "CVE-2020-0198", "CVE-2020-13112", "CVE-2020-13113", "CVE-2020-13114" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-06 16:01:00 +0000 (Mon, 06 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-06-17 03:00:18 +0000 (Wed, 17 Jun 2020)" );
	script_name( "Ubuntu: Security Advisory for libexif (USN-4396-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "USN", value: "4396-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-June/005480.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libexif'
  package(s) announced via the USN-4396-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libexif incorrectly handled certain inputs.
An attacker could possibly use this issue to expose sensitive information.
(CVE-2020-0093, CVE-2020-0182)

It was discovered that libexif incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a remote denial of service.
(CVE-2020-0198)

It was discovered that libexif incorrectly handled certain inputs.
An attacker could possibly use this issue to expose sensitive information or
cause a crash. (CVE-2020-13112)

It was discovered that libexif incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a crash.
(CVE-2020-13113)

It was discovered libexif incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2020-13114)" );
	script_tag( name: "affected", value: "'libexif' package(s) on Ubuntu 20.04 LTS, Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libexif12", ver: "0.6.21-5.1ubuntu0.5", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libexif12", ver: "0.6.21-4ubuntu0.5", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libexif12", ver: "0.6.21-2ubuntu0.5", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libexif12", ver: "0.6.21-6ubuntu0.3", rls: "UBUNTU20.04 LTS" ) )){
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

