if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844306" );
	script_version( "2021-07-09T02:00:48+0000" );
	script_cve_id( "CVE-2019-15795", "CVE-2019-15796" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-09 02:00:48 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-08 18:23:00 +0000 (Wed, 08 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-01-23 04:00:32 +0000 (Thu, 23 Jan 2020)" );
	script_name( "Ubuntu Update for python-apt USN-4247-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.10|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4247-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-January/005285.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-apt'
  package(s) announced via the USN-4247-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4247-1 fixed vulnerabilities in python-apt. The updated packages caused
a regression when attempting to upgrade to a new Ubuntu release. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

It was discovered that python-apt would still use MD5 hashes to validate
certain downloaded packages. If a remote attacker were able to perform a
man-in-the-middle attack, this flaw could potentially be used to install
altered packages. (CVE-2019-15795)
It was discovered that python-apt could install packages from untrusted
repositories, contrary to expectations. (CVE-2019-15796)" );
	script_tag( name: "affected", value: "'python-apt' package(s) on Ubuntu 19.10, Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "python-apt", ver: "1.6.5ubuntu0.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apt", ver: "1.6.5ubuntu0.2", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "python-apt", ver: "1.9.0ubuntu1.3", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apt", ver: "1.9.0ubuntu1.3", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "python-apt", ver: "1.8.5~ubuntu0.3", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apt", ver: "1.8.5~ubuntu0.3", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "python-apt", ver: "1.1.0~beta1ubuntu0.16.04.8", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apt", ver: "1.1.0~beta1ubuntu0.16.04.8", rls: "UBUNTU16.04 LTS" ) )){
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

