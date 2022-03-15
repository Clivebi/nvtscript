if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842926" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-10-21 05:54:08 +0200 (Fri, 21 Oct 2016)" );
	script_cve_id( "CVE-2016-5195" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-snapdragon USN-3106-4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-snapdragon'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that a race condition
  existed in the memory manager of the Linux kernel when handling copy-on-write
  breakage of private read-only memory mappings. A local attacker could use this
  to gain administrative privileges." );
	script_tag( name: "affected", value: "linux-snapdragon on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3106-4" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3106-4/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1032-snapdragon", ver: "4.4.0-1032.36", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

