if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843433" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2018-01-27 07:49:01 +0100 (Sat, 27 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-azure USN-3548-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-azure'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3548-1 fixed vulnerabilities in the
  Linux kernel for Ubuntu 17.10. This update provides the corresponding updates
  for the Linux Hardware Enablement (HWE) kernel from Ubuntu 17.10 for Ubuntu
  16.04 LTS. Jay Vosburgh discovered a logic error in the x86-64 syscall entry
  implementation in the Linux kernel, introduced as part of the mitigations for
  the Spectre vulnerability. A local attacker could use this to cause a denial of
  service or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "linux-azure on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3548-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3548-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1007-azure", ver: "4.13.0-1007.9", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1008-gcp", ver: "4.13.0-1008.11", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1019-oem", ver: "4.13.0-1019.20", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-32-generic", ver: "4.13.0-32.35~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-32-lowlatency", ver: "4.13.0-32.35~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-azure", ver: "4.13.0.1007.8", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "4.13.0.1008.10", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-hwe-16.04", ver: "4.13.0.32.52", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gke", ver: "4.13.0.1008.10", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-hwe-16.04", ver: "4.13.0.32.52", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-oem", ver: "4.13.0.1019.23", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

