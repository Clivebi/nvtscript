if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842536" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-18 06:36:13 +0100 (Wed, 18 Nov 2015)" );
	script_cve_id( "CVE-2015-1342", "CVE-2015-1344" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for lxcfs USN-2813-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lxcfs'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that LXCFS incorrectly
enforced directory escapes. A local attacker could use this issue to possibly
escalate privileges. (CVE-2015-1342)

It was discovered that LXCFS incorrectly checked certain permissions. A
local attacker could use this issue t possibly escalate privileges.
(CVE-2015-1344)" );
	script_tag( name: "affected", value: "lxcfs on Ubuntu 15.10,
  Ubuntu 15.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2813-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2813-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "lxcfs", ver: "0.7-0ubuntu4.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "lxcfs", ver: "0.10-0ubuntu2.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

