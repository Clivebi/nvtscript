if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842994" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-12-17 05:31:20 +0100 (Sat, 17 Dec 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for apt USN-3156-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3156-1 fixed vulnerabilities in APT.
  It also caused a bug in unattended-upgrades on that may require manual
  intervention to repair.

Users on Ubuntu 16.10 should run the following commands at a
terminal:

sudo dpkg --configure --pending
sudo apt-get -f install

This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

Jann Horn discovered that APT incorrectly handled InRelease files.
If a remote attacker were able to perform a man-in-the-middle attack,
this flaw could potentially be used to install altered packages." );
	script_tag( name: "affected", value: "apt on Ubuntu 16.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3156-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3156-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.10" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "apt", ver: "1.3.3", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

