if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843348" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-25 15:05:59 +0200 (Wed, 25 Oct 2017)" );
	script_cve_id( "CVE-2017-10155", "CVE-2017-10165", "CVE-2017-10167", "CVE-2017-10384", "CVE-2017-10227", "CVE-2017-10268", "CVE-2017-10276", "CVE-2017-10283", "CVE-2017-10286", "CVE-2017-10294", "CVE-2017-10311", "CVE-2017-10313", "CVE-2017-10314", "CVE-2017-10320", "CVE-2017-10378", "CVE-2017-10379" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-14 02:29:00 +0000 (Thu, 14 Dec 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for mysql-5.7 USN-3459-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-5.7'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in
  MySQL and this update includes new upstream MySQL versions to fix these issues.
  MySQL has been updated to 5.5.58 in Ubuntu 14.04 LTS. Ubuntu 16.04 LTS, Ubuntu
  17.04 and Ubuntu 17.10 have been updated to MySQL 5.7.20. In addition to
  security fixes, the updated packages contain bug fixes, new features, and
  possibly incompatible changes. Please see the references for more information." );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-58.html" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-20.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html" );
	script_tag( name: "affected", value: "mysql-5.7 on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3459-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3459-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.5", ver: "5.5.58-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.20-0ubuntu0.17.04.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.20-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

