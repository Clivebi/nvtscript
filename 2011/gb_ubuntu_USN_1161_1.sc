if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1161-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840698" );
	script_version( "2021-05-19T13:10:04+0000" );
	script_tag( name: "last_modification", value: "2021-05-19 13:10:04 +0000 (Wed, 19 May 2021)" );
	script_tag( name: "creation_date", value: "2011-07-18 15:23:56 +0200 (Mon, 18 Jul 2011)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 20:08:00 +0000 (Mon, 27 Jul 2020)" );
	script_xref( name: "USN", value: "1161-1" );
	script_cve_id( "CVE-2010-3881", "CVE-2011-1017", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1748", "CVE-2011-1745", "CVE-2011-2022", "CVE-2011-1746", "CVE-2011-1747", "CVE-2011-1770" );
	script_name( "Ubuntu Update for linux-ec2 USN-1161-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1161-1" );
	script_tag( name: "affected", value: "linux-ec2 on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Vasiliy Kulikov discovered that kvm did not correctly clear memory. A local
  attacker could exploit this to read portions of the kernel stack, leading
  to a loss of privacy. (CVE-2010-3881)

  Timo Warns discovered that the LDM disk partition handling code did not
  correctly handle certain values. By inserting a specially crafted disk
  device, a local attacker could exploit this to gain root privileges.
  (CVE-2011-1017)

  Neil Horman discovered that NFSv4 did not correctly handle certain orders
  of operation with ACL data. A remote attacker with access to an NFSv4 mount
  could exploit this to crash the system, leading to a denial of service.
  (CVE-2011-1090)

  Timo Warns discovered that OSF partition parsing routines did not correctly
  clear memory. A local attacker with physical access could plug in a
  specially crafted block device to read kernel memory, leading to a loss of
  privacy. (CVE-2011-1163)

  Dan Rosenberg discovered that MPT devices did not correctly validate
  certain values in ioctl calls. If these drivers were loaded, a local
  attacker could exploit this to read arbitrary kernel memory, leading to a
  loss of privacy. (CVE-2011-1494, CVE-2011-1495)

  Tavis Ormandy discovered that the pidmap function did not correctly handle
  large requests. A local attacker could exploit this to crash the system,
  leading to a denial of service. (CVE-2011-1593)

  Oliver Hartkopp and Dave Jones discovered that the CAN network driver did
  not correctly validate certain socket structures. If this driver was
  loaded, a local attacker could crash the system, leading to a denial of
  service. (CVE-2011-1598, CVE-2011-1748)

  Vasiliy Kulikov discovered that the AGP driver did not check certain ioctl
  values. A local attacker with access to the video subsystem could exploit
  this to crash the system, leading to a denial of service, or possibly gain
  root privileges. (CVE-2011-1745, CVE-2011-2022)

  Vasiliy Kulikov discovered that the AGP driver did not check the size of
  certain memory allocations. A local attacker with access to the video
  subsystem could exploit this to run the system out of memory, leading to a
  denial of service. (CVE-2011-1746, CVE-2011-1747)

  Dan Rosenberg discovered that the DCCP stack did not correctly handle
  certain packet structures. A remote attacker could exploit this to crash
  the system, leading to a denial of service. (CVE-2011-1770)" );
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
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-317-ec2", ver: "2.6.32-317.36", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

