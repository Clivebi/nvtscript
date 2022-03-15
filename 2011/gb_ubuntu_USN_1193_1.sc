if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1193-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840726" );
	script_version( "2020-11-12T12:15:05+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 12:15:05 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-08-24 09:14:07 +0200 (Wed, 24 Aug 2011)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_xref( name: "USN", value: "1193-1" );
	script_cve_id( "CVE-2011-1577", "CVE-2011-1581", "CVE-2011-2484", "CVE-2011-2493" );
	script_name( "Ubuntu Update for linux USN-1193-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1193-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Timo Warns discovered that the GUID partition parsing routines did not
  correctly validate certain structures. A local attacker with physical
  access could plug in a specially crafted block device to crash the system,
  leading to a denial of service. (CVE-2011-1577)

  Phil Oester discovered that the network bonding system did not correctly
  handle large queues. On some systems, a remote attacker could send
  specially crafted traffic to crash the system, leading to a denial of
  service. (CVE-2011-1581)

  Vasiliy Kulikov discovered that taskstats listeners were not correctly
  handled. A local attacker could exploit this to exhaust memory and CPU
  resources, leading to a denial of service. (CVE-2011-2484)

  Sami Liedes discovered that ext4 did not correctly handle missing root
  inodes. A local attacker could trigger the mount of a specially crafted
  filesystem to cause the system to crash, leading to a denial of service.
  (CVE-2011-2493)" );
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
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-11-generic", ver: "2.6.38-11.48", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-11-generic-pae", ver: "2.6.38-11.48", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-11-omap", ver: "2.6.38-11.48", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-11-powerpc", ver: "2.6.38-11.48", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-11-powerpc-smp", ver: "2.6.38-11.48", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-11-powerpc64-smp", ver: "2.6.38-11.48", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-11-server", ver: "2.6.38-11.48", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-11-versatile", ver: "2.6.38-11.48", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-11-virtual", ver: "2.6.38-11.48", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

