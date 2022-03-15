if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843758" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_cve_id( "CVE-2017-16548", "CVE-2018-5764" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-01 14:14:00 +0000 (Fri, 01 May 2020)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:15:47 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for rsync USN-3543-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3543-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3543-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rsync'
  package(s) announced via the USN-3543-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that rsync incorrectly handled certain data input.
An attacker could possibly use this to cause a denial of service or
execute arbitrary code. (CVE-2017-16548)

It was discovered that rsync incorrectly parsed certain arguments. An
attacker could possibly use this to bypass arguments and execute
arbitrary code. (CVE-2018-5764)" );
	script_tag( name: "affected", value: "rsync on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
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
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "rsync", ver: "3.1.0-2ubuntu0.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "rsync", ver: "3.1.2-2ubuntu0.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "rsync", ver: "3.1.1-3ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

