if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842570" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-18 05:44:37 +0100 (Fri, 18 Dec 2015)" );
	script_cve_id( "CVE-2014-3925", "CVE-2015-7529" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for sosreport USN-2845-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sosreport'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Dolev Farhi discovered an information
disclosure issue in SoS. If the /etc/fstab file contained passwords, the
passwords were included in the SoS report. This issue only affected Ubuntu 14.04
LTS. (CVE-2014-3925)

Mateusz Guzik discovered that SoS incorrectly handled temporary files. A
local attacker could possibly use this issue to overwrite arbitrary files
or gain access to temporary file contents containing sensitive system
information. (CVE-2015-7529)" );
	script_tag( name: "affected", value: "sosreport on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2845-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2845-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.04"){
	if(( res = isdpkgvuln( pkg: "sosreport", ver: "3.2-2ubuntu0.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "sosreport", ver: "3.1-1ubuntu2.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "sosreport", ver: "3.2-2ubuntu1.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
