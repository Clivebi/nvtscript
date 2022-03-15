if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844814" );
	script_version( "2021-08-18T06:00:55+0000" );
	script_cve_id( "CVE-2021-25682", "CVE-2021-25683", "CVE-2021-25684" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-18 06:00:55 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-22 14:21:00 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-02-03 04:00:47 +0000 (Wed, 03 Feb 2021)" );
	script_name( "Ubuntu: Security Advisory for apport (USN-4720-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4720-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-February/005873.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apport'
  package(s) announced via the USN-4720-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Itai Greenhut discovered that Apport incorrectly parsed certain files in
the /proc filesystem. A local attacker could use this issue to escalate
privileges and run arbitrary code. (CVE-2021-25682, CVE-2021-25683)

Itai Greenhut discovered that Apport incorrectly handled opening certain
special files. A local attacker could possibly use this issue to cause
Apport to hang, resulting in a denial of service. (CVE-2021-25684)" );
	script_tag( name: "affected", value: "'apport' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "apport", ver: "2.20.11-0ubuntu27.16", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apport", ver: "2.20.11-0ubuntu27.16", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "apport", ver: "2.20.9-0ubuntu7.23", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python-apport", ver: "2.20.9-0ubuntu7.23", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apport", ver: "2.20.9-0ubuntu7.23", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "apport", ver: "2.20.1-0ubuntu2.30", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python-apport", ver: "2.20.1-0ubuntu2.30", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apport", ver: "2.20.1-0ubuntu2.30", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "apport", ver: "2.20.11-0ubuntu50.5", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apport", ver: "2.20.11-0ubuntu50.5", rls: "UBUNTU20.10" ) )){
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

