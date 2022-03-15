if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844055" );
	script_version( "2019-12-12T11:35:23+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-12 11:35:23 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-06-20 02:00:33 +0000 (Thu, 20 Jun 2019)" );
	script_name( "Ubuntu Update for evince USN-4024-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4024-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-June/004969.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'evince'
  package(s) announced via the USN-4024-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "As a security improvement, this update adjusts the AppArmor profile for the
Evince thumbnailer to reduce access to the system and adjusts the AppArmor
profile for Evince and Evince previewer to limit access to the DBus system
bus. Additionally adjust the evince abstraction to disallow writes on
parent directories of sensitive files." );
	script_tag( name: "affected", value: "'evince' package(s) on Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "evince-common", ver: "3.28.4-0ubuntu1.2", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "evince-common", ver: "3.18.2-1ubuntu4.5", rls: "UBUNTU16.04 LTS" ) )){
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

