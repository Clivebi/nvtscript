if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843760" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_cve_id( "CVE-2018-0499" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-28 17:46:00 +0000 (Tue, 28 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:15:55 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for xapian-core USN-3709-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(17\\.10|18\\.04 LTS)" );
	script_xref( name: "USN", value: "3709-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3709-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xapian-core'
  package(s) announced via the USN-3709-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Xapian-core incorrectly handled certain files.
An attacker could possibly use this to execute arbitrary code." );
	script_tag( name: "affected", value: "xapian-core on Ubuntu 18.04 LTS,
  Ubuntu 17.10." );
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
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "libxapian30", ver: "1.4.4-2ubuntu0.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xapian-tools", ver: "1.4.4-2ubuntu0.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libxapian30", ver: "1.4.5-1ubuntu0.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xapian-tools", ver: "1.4.5-1ubuntu0.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

