if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842777" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-06-01 05:24:18 +0200 (Wed, 01 Jun 2016)" );
	script_cve_id( "CVE-2016-1581", "CVE-2016-1582" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for lxd USN-2988-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lxd'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Robie Basak discovered that LXD incorrectly
  set permissions when setting up a loop based ZFS pool. A local attacker could
  use this issue to copy and read the data of any LXD container. (CVE-2016-1581)

  Robie Basak discovered that LXD incorrectly set permissions when switching
  an unprivileged container into privileged mode. A local attacker could use
  this issue to access any world readable path in the container directory,
  including setuid binaries. (CVE-2016-1582)" );
	script_tag( name: "affected", value: "lxd on Ubuntu 16.04 LTS,
  Ubuntu 15.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2988-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2988-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(16\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "lxd", ver: "2.0.2-0ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "lxd", ver: "0.20-0ubuntu4.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

