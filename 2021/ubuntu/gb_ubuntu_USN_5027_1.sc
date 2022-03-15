if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.845016" );
	script_version( "2021-08-18T06:00:55+0000" );
	script_cve_id( "CVE-2021-32610" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-18 06:00:55 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-06 20:47:00 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-30 03:00:44 +0000 (Fri, 30 Jul 2021)" );
	script_name( "Ubuntu: Security Advisory for php-pear (USN-5027-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "Advisory-ID", value: "USN-5027-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-July/006126.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-pear'
  package(s) announced via the USN-5027-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that PEAR incorrectly handled symbolic links in archives.
A remote attacker could possibly use this issue to execute arbitrary code." );
	script_tag( name: "affected", value: "'php-pear' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "php-pear", ver: "1:1.10.5+submodules+notgz-1ubuntu1.18.04.4", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "php-pear", ver: "1:1.10.9+submodules+notgz-1ubuntu0.20.04.3", rls: "UBUNTU20.04 LTS" ) )){
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

