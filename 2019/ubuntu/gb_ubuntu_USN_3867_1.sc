if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843880" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2019-2420", "CVE-2019-2434", "CVE-2019-2455", "CVE-2019-2481", "CVE-2019-2482", "CVE-2019-2486", "CVE-2019-2503", "CVE-2019-2507", "CVE-2019-2510", "CVE-2019-2528", "CVE-2019-2529", "CVE-2019-2531", "CVE-2019-2532", "CVE-2019-2534", "CVE-2019-2537" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-24 04:01:35 +0100 (Thu, 24 Jan 2019)" );
	script_name( "Ubuntu Update for mysql-5.7 USN-3867-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(18\\.04 LTS|18\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3867-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3867-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'mysql-5.7' package(s) announced via the USN-3867-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
  is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered
  in MySQL and this update includes a new upstream MySQL version to fix these
  issues.

Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 18.10 have been updated to
MySQL 5.7.25.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes." );
	script_tag( name: "affected", value: "mysql-5.7 on Ubuntu 18.10,
  Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.25-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.25-0ubuntu0.18.10.2", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.25-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

