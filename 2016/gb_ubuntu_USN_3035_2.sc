if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842829" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-07-15 05:27:21 +0200 (Fri, 15 Jul 2016)" );
	script_cve_id( "CVE-2016-3070" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-raspi2 USN-3035-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-raspi2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Jan Stancek discovered that the Linux kernel's
  memory manager did not properly handle moving pages mapped by the asynchronous I/O
  (AIO) ring buffer to the other nodes. A local attacker could use this to cause a
  denial of service (system crash)." );
	script_tag( name: "affected", value: "linux-raspi2 on Ubuntu 15.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3035-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3035-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU15\\.10" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-1034-raspi2", ver: "4.2.0-1034.44", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

