if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844747" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_cve_id( "CVE-2020-16128", "CVE-2020-27349" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-11 17:54:00 +0000 (Fri, 11 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-09 04:00:29 +0000 (Wed, 09 Dec 2020)" );
	script_name( "Ubuntu: Security Advisory for aptdaemon (USN-4664-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "USN", value: "4664-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-December/005796.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aptdaemon'
  package(s) announced via the USN-4664-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Kevin Backhouse discovered that Aptdaemon incorrectly handled certain
properties. A local attacker could use this issue to test for the presence
of local files. (CVE-2020-16128)

Kevin Backhouse discovered that Aptdaemon incorrectly handled permission
checks. A local attacker could possibly use this issue to cause a denial of
service. (CVE-2020-27349)" );
	script_tag( name: "affected", value: "'aptdaemon' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "aptdaemon", ver: "1.1.1+bzr982-0ubuntu32.3", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "aptdaemon", ver: "1.1.1+bzr982-0ubuntu19.5", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "aptdaemon", ver: "1.1.1+bzr982-0ubuntu14.5", rls: "UBUNTU16.04 LTS" ) )){
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
if(release == "UBUNTU20.10"){
	if(!isnull( res = isdpkgvuln( pkg: "aptdaemon", ver: "1.1.1+bzr982-0ubuntu34.1", rls: "UBUNTU20.10" ) )){
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

