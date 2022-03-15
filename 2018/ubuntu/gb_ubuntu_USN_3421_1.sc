if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843669" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_cve_id( "CVE-2017-14062" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-07 20:17:00 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:05:03 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for libidn2-0 USN-3421-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU17\\.04" );
	script_xref( name: "USN", value: "3421-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3421-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libidn2-0'
  package(s) announced via the USN-3421-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Libidn2 incorrectly handled certain input. A
remote attacker could possibly use this issue to cause Libidn2 to
crash, resulting in a denial of service." );
	script_tag( name: "affected", value: "libidn2-0 on Ubuntu 17.04." );
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
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "idn2", ver: "0.16-1ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libidn2-0", ver: "0.16-1ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

