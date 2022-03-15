if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842438" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-09-17 06:18:57 +0200 (Thu, 17 Sep 2015)" );
	script_cve_id( "CVE-2015-1319" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for unity-settings-daemon USN-2741-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'unity-settings-daemon'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Unity Settings
Daemon incorrectly allowed removable media to be mounted when the screen is
locked. If a vulnerability were discovered in some other desktop component, such
as an image library, a local attacker could possibly use this issue to gain access
to the session." );
	script_tag( name: "affected", value: "unity-settings-daemon on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2741-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2741-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "unity-settings-daemon", ver: "14.04.0+14.04.20150825-0ubuntu2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

