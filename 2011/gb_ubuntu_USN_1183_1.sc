if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1183-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840716" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-12 15:49:01 +0200 (Fri, 12 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1183-1" );
	script_cve_id( "CVE-2010-4076", "CVE-2010-4077", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1577", "CVE-2011-1598", "CVE-2011-1746" );
	script_name( "Ubuntu Update for linux USN-1183-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1183-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Dan Rosenberg discovered that multiple terminal ioctls did not correctly
  initialize structure memory. A local attacker could exploit this to read
  portions of kernel stack memory, leading to a loss of privacy.
  (CVE-2010-4076, CVE-2010-4077)

  Neil Horman discovered that NFSv4 did not correctly handle certain orders
  of operation with ACL data. A remote attacker with access to an NFSv4 mount
  could exploit this to crash the system, leading to a denial of service.
  (CVE-2011-1090)

  Timo Warns discovered that OSF partition parsing routines did not correctly
  clear memory. A local attacker with physical access could plug in a
  specially crafted block device to read kernel memory, leading to a loss of
  privacy. (CVE-2011-1163)

  Timo Warns discovered that the GUID partition parsing routines did not
  correctly validate certain structures. A local attacker with physical
  access could plug in a specially crafted block device to crash the system,
  leading to a denial of service. (CVE-2011-1577)

  Oliver Hartkopp and Dave Jones discovered that the CAN network driver did
  not correctly validate certain socket structures. If this driver was
  loaded, a local attacker could crash the system, leading to a denial of
  service. (CVE-2011-1598)

  Vasiliy Kulikov discovered that the AGP driver did not check the size of
  certain memory allocations. A local attacker with access to the video
  subsystem could exploit this to run the system out of memory, leading to a
  denial of service. (CVE-2011-1746)" );
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
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-30-generic", ver: "2.6.35-30.56", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-30-generic-pae", ver: "2.6.35-30.56", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-30-omap", ver: "2.6.35-30.56", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-30-powerpc", ver: "2.6.35-30.56", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-30-powerpc-smp", ver: "2.6.35-30.56", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-30-powerpc64-smp", ver: "2.6.35-30.56", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-30-server", ver: "2.6.35-30.56", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-30-versatile", ver: "2.6.35-30.56", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-30-virtual", ver: "2.6.35-30.56", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

