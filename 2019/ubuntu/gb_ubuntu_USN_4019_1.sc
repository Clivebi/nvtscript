if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844058" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2017-2518", "CVE-2017-2520", "CVE-2018-20505", "CVE-2018-20346", "CVE-2018-20506", "CVE-2019-8457", "CVE-2019-9936", "CVE-2019-9937", "CVE-2016-6153", "CVE-2017-10989", "CVE-2017-13685", "CVE-2017-2519" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-06-20 02:00:35 +0000 (Thu, 20 Jun 2019)" );
	script_name( "Ubuntu Update for sqlite3 USN-4019-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.10|UBUNTU19\\.04|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4019-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-June/004964.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sqlite3'
  package(s) announced via the USN-4019-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that SQLite incorrectly handled certain SQL files.
An attacker could possibly use this issue to execute arbitrary code
or cause a denial of service. This issue only affected Ubuntu 16.04
LTS. (CVE-2017-2518, CVE-2017-2520)

It was discovered that SQLite incorrectly handled certain queries.
An attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-20505)

It was discovered that SQLite incorrectly handled certain queries.
An attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and
Ubuntu 18.10. (CVE-2018-20346, CVE-2018-20506)

It was discovered that SQLite incorrectly handled certain inputs.
An attacker could possibly use this issue to access sensitive information.
(CVE-2019-8457)

It was discovered that SQLite incorrectly handled certain queries.
An attacker could possibly use this issue to access sensitive information.
This issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 18.10.
(CVE-2019-9936)

It was discovered that SQLite incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a crash or execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS
and Ubuntu 18.10. (CVE-2019-9937)

It was discovered that SQLite incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 16.04 LTS. (CVE-2016-6153)

It was discovered that SQLite incorrectly handled certain databases.
An attacker could possibly use this issue to access sensitive information.
This issue only affected Ubuntu 16.04 LTS. (CVE-2017-10989)

It was discovered that SQLite incorrectly handled certain files.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 16.04 LTS. (CVE-2017-13685)

It was discovered that SQLite incorrectly handled certain queries.
An attacker could possibly use this issue to execute arbitrary code or
cause a denial of service. This issue only affected Ubuntu 16.04 LTS.
(CVE-2017-2519)" );
	script_tag( name: "affected", value: "'sqlite3' package(s) on Ubuntu 19.04, Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU18.10"){
	if(!isnull( res = isdpkgvuln( pkg: "libsqlite3-0", ver: "3.24.0-1ubuntu0.1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "sqlite3", ver: "3.24.0-1ubuntu0.1", rls: "UBUNTU18.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libsqlite3-0", ver: "3.27.2-2ubuntu0.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "sqlite3", ver: "3.27.2-2ubuntu0.1", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libsqlite3-0", ver: "3.22.0-1ubuntu0.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "sqlite3", ver: "3.22.0-1ubuntu0.1", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libsqlite3-0", ver: "3.11.0-1ubuntu1.2", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "sqlite3", ver: "3.11.0-1ubuntu1.2", rls: "UBUNTU16.04 LTS" ) )){
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

