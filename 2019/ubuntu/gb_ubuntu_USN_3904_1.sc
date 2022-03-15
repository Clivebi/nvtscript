if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843928" );
	script_version( "$Revision: 14288 $" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2019-03-08 04:08:31 +0100 (Fri, 08 Mar 2019)" );
	script_name( "Ubuntu Update for nvidia-graphics-drivers-390 USN-3904-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(18\\.04 LTS|18\\.10)" );
	script_xref( name: "USN", value: "3904-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3904-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'nvidia-graphics-drivers-390' package(s) announced via the USN-3904-1
  advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
  is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the NVIDIA graphics
  drivers incorrectly handled the GPU performance counters. A local attacker
  could possibly use this issue to access the application data processed on
  the GPU." );
	script_tag( name: "affected", value: "nvidia-graphics-drivers-390 on Ubuntu 18.10,
  Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-390", ver: "390.116-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-390", ver: "390.116-0ubuntu0.18.10.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

