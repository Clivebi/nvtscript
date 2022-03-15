if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843667" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-24 06:34:42 +0200 (Wed, 24 Oct 2018)" );
	script_cve_id( "CVE-2018-3133", "CVE-2018-3143", "CVE-2018-3144", "CVE-2018-3155", "CVE-2018-3156", "CVE-2018-3161", "CVE-2018-3162", "CVE-2018-3171", "CVE-2018-3173", "CVE-2018-3174", "CVE-2018-3185", "CVE-2018-3187", "CVE-2018-3200", "CVE-2018-3247", "CVE-2018-3251", "CVE-2018-3276", "CVE-2018-3277", "CVE-2018-3278", "CVE-2018-3282", "CVE-2018-3283", "CVE-2018-3284" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for mysql-5.7 USN-3799-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-5.7'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.5.62 in Ubuntu 14.04 LTS. Ubuntu 16.04 LTS,
Ubuntu 18.04 LTS, and Ubuntu 18.10 have been updated to MySQL 5.7.24.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes." );
	script_tag( name: "affected", value: "mysql-5.7 on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3799-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3799-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "mysql-server-5.5", ver: "5.5.62-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.24-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.24-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

