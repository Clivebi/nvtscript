if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844812" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2021-2002", "CVE-2021-2010", "CVE-2021-2011", "CVE-2021-2014", "CVE-2021-2021", "CVE-2021-2022", "CVE-2021-2024", "CVE-2021-2031", "CVE-2021-2032", "CVE-2021-2036", "CVE-2021-2038", "CVE-2021-2046", "CVE-2021-2048", "CVE-2021-2056", "CVE-2021-2058", "CVE-2021-2060", "CVE-2021-2061", "CVE-2021-2065", "CVE-2021-2070", "CVE-2021-2072", "CVE-2021-2076", "CVE-2021-2081", "CVE-2021-2087", "CVE-2021-2088", "CVE-2021-2122" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-22 09:15:00 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-02-02 04:00:33 +0000 (Tue, 02 Feb 2021)" );
	script_name( "Ubuntu: Security Advisory for mysql-8.0 (USN-4716-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4716-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-February/005867.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-8.0'
  package(s) announced via the USN-4716-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.23 in Ubuntu 20.04 LTS and Ubuntu 20.10.
Ubuntu 16.04 LTS and Ubuntu 18.04 LTS have been updated to MySQL 5.7.33.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes." );
	script_tag( name: "affected", value: "'mysql-8.0' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "mysql-server-8.0", ver: "8.0.23-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.33-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.33-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "mysql-server-8.0", ver: "8.0.23-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
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

