if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842214" );
	script_version( "2019-04-30T06:00:47+0000" );
	script_tag( name: "last_modification", value: "2019-04-30 06:00:47 +0000 (Tue, 30 Apr 2019)" );
	script_tag( name: "creation_date", value: "2015-06-09 11:07:21 +0200 (Tue, 09 Jun 2015)" );
	script_cve_id( "CVE-2015-1326" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for python-dbusmock USN-2618-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-dbusmock'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that python-dbusmock
incorrectly handled template loading from shared directories. A local attacker
could possibly use this issue to execute arbitrary code." );
	script_tag( name: "affected", value: "python-dbusmock on Ubuntu 14.10,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2618-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2618-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "python-dbusmock", ver: "0.11.4-1ubuntu1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-dbusmock", ver: "0.11.4-1ubuntu1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python-dbusmock", ver: "0.10.1-1ubuntu1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-dbusmock", ver: "0.10.1-1ubuntu1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
