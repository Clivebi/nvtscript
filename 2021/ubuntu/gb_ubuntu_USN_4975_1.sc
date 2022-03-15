if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844964" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2021-32052", "CVE-2021-33203", "CVE-2021-33571" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-17 15:49:00 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-03 03:00:35 +0000 (Thu, 03 Jun 2021)" );
	script_name( "Ubuntu: Security Advisory for python-django (USN-4975-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4975-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-June/006053.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-django'
  package(s) announced via the USN-4975-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Django URLValidator function incorrectly handled
newlines and tabs. A remote attacker could possibly use this issue to
perform a header injection attack. This issue only affected Ubuntu 20.04
LTS, Ubuntu 20.10, and Ubuntu 21.04. (CVE-2021-32052)

Rasmus Lerchedahl Petersen and Rasmus Wriedt Larsen discovered that Django
incorrectly handled path sanitation in admindocs. A remote attacker could
possibly use this issue to determine the existence of arbitrary files and
in certain configurations obtain their contents. (CVE-2021-33203)

It was discovered that Django incorrectly handled IPv4 addresses with
leading zeros. A remote attacker could possibly use this issue to perform a
wide variety of attacks, including bypassing certain access restrictions.
(CVE-2021-33571)" );
	script_tag( name: "affected", value: "'python-django' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "python3-django", ver: "2:2.2.12-1ubuntu0.7", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "python-django", ver: "1:1.11.11-1ubuntu1.14", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-django", ver: "1:1.11.11-1ubuntu1.14", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "python3-django", ver: "2:2.2.16-1ubuntu0.5", rls: "UBUNTU20.10" ) )){
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

