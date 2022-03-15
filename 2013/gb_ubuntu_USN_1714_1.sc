if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1714-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841308" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-02-08 10:18:50 +0530 (Fri, 08 Feb 2013)" );
	script_cve_id( "CVE-2013-0241" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "USN", value: "1714-1" );
	script_name( "Ubuntu Update for xserver-xorg-video-qxl USN-1714-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xserver-xorg-video-qxl'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10)" );
	script_tag( name: "affected", value: "xserver-xorg-video-qxl on Ubuntu 12.04 LTS,
  Ubuntu 11.10" );
	script_tag( name: "insight", value: "It was discovered that the QXL graphics driver incorrectly handled
  terminated connections. An attacker that could connect to a guest using
  SPICE and the QXL graphics driver could cause the guest to hang or crash,
  resulting in a denial of service." );
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
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "xserver-xorg-video-qxl", ver: "0.0.16-2ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "xserver-xorg-video-qxl", ver: "0.0.14-1ubuntu0.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

