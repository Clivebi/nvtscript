if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844105" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2017-7481", "CVE-2018-10855", "CVE-2018-16837", "CVE-2018-16876", "CVE-2019-10156", "CVE-2018-10874", "CVE-2018-10875", "CVE-2019-3828" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-28 16:38:00 +0000 (Thu, 28 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-07-25 02:01:29 +0000 (Thu, 25 Jul 2019)" );
	script_name( "Ubuntu Update for ansible USN-4072-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4072-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-July/005031.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ansible'
  package(s) announced via the USN-4072-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Ansible failed to properly handle sensitive information.
A local attacker could use those vulnerabilities to extract them.
(CVE-2017-7481)
(CVE-2018-10855)
(CVE-2018-16837)
(CVE-2018-16876)
(CVE-2019-10156)

It was discovered that Ansible could load configuration files from the current
working directory containing crafted commands. An attacker could run arbitrary
code as result.
(CVE-2018-10874)
(CVE-2018-10875)

It was discovered that Ansible fetch module had a path traversal vulnerability.
A local attacker could copy and overwrite files outside of the specified
destination.
(CVE-2019-3828)" );
	script_tag( name: "affected", value: "'ansible' package(s) on Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "ansible", ver: "2.5.1+dfsg-1ubuntu0.1", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "ansible", ver: "2.7.8+dfsg-1ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "ansible", ver: "2.0.0.2-2ubuntu1.3", rls: "UBUNTU16.04 LTS" ) )){
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

