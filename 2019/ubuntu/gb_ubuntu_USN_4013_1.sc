if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844048" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2017-14245", "CVE-2017-14246", "CVE-2017-14634", "CVE-2017-16942", "CVE-2017-17456", "CVE-2017-17457", "CVE-2017-6892", "CVE-2018-13139", "CVE-2018-19432", "CVE-2018-19661", "CVE-2018-19662", "CVE-2018-19758", "CVE-2019-3832" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-29 19:15:00 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-06-11 02:01:11 +0000 (Tue, 11 Jun 2019)" );
	script_name( "Ubuntu Update for libsndfile USN-4013-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU18\\.10|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4013-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-June/004952.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsndfile'
  package(s) announced via the USN-4013-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libsndfile incorrectly handled certain malformed
files. A remote attacker could use this issue to cause libsndfile to crash,
resulting in a denial of service, or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "'libsndfile' package(s) on Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libsndfile1", ver: "1.0.28-4ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU18.10"){
	if(!isnull( res = isdpkgvuln( pkg: "libsndfile1", ver: "1.0.28-4ubuntu0.18.10.1", rls: "UBUNTU18.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libsndfile1", ver: "1.0.25-10ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) )){
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

