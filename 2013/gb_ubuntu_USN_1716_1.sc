if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1716-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841314" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-02-15 11:25:14 +0530 (Fri, 15 Feb 2013)" );
	script_cve_id( "CVE-2013-1050" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1716-1" );
	script_name( "Ubuntu Update for gnome-screensaver USN-1716-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnome-screensaver'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.10" );
	script_tag( name: "affected", value: "gnome-screensaver on Ubuntu 12.10" );
	script_tag( name: "insight", value: "It was discovered that gnome-screensaver did not start automatically after
  logging in. This may result in the screen not being automatically locked
  after the inactivity timeout is reached, permitting an attacker with
  physical access to gain access to an unlocked session." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "gnome-screensaver", ver: "3.6.0-0ubuntu2.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

