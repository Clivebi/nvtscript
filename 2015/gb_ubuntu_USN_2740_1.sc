if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842437" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-09-17 06:18:53 +0200 (Thu, 17 Sep 2015)" );
	script_cve_id( "CVE-2015-1270", "CVE-2015-2632", "CVE-2015-4760" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for icu USN-2740-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icu'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Atte Kettunen discovered that ICU
incorrectly handled certain converter names. If an application using ICU processed
crafted data, a remote attacker could possibly cause it to crash. (CVE-2015-1270)

It was discovered that ICU incorrectly handled certain memory operations
when processing data. If an application using ICU processed crafted data,
a remote attacker could possibly cause it to crash or potentially execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2015-2632, CVE-2015-4760)" );
	script_tag( name: "affected", value: "icu on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2740-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2740-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libicu52:amd64", ver: "52.1-3ubuntu0.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libicu52:i386", ver: "52.1-3ubuntu0.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libicu48", ver: "4.8.1.1-3ubuntu0.6", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

