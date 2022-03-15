if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1241-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840790" );
	script_version( "2020-08-04T07:16:50+0000" );
	script_tag( name: "last_modification", value: "2020-08-04 07:16:50 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-10-31 13:45:00 +0100 (Mon, 31 Oct 2011)" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1241-1" );
	script_cve_id( "CVE-2011-1573", "CVE-2011-1576", "CVE-2011-1776", "CVE-2011-2213", "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2496", "CVE-2011-2497", "CVE-2011-2517", "CVE-2011-2525", "CVE-2011-2695", "CVE-2011-2723", "CVE-2011-2905", "CVE-2011-2909", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3363" );
	script_name( "Ubuntu Update for linux-fsl-imx51 USN-1241-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1241-1" );
	script_tag( name: "affected", value: "linux-fsl-imx51 on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that the Stream Control Transmission Protocol (SCTP)
  implementation incorrectly calculated lengths. If the net.sctp.addip_enable
  variable was turned on, a remote attacker could send specially crafted
  traffic to crash the system. (CVE-2011-1573)

  Ryan Sweat discovered that the kernel incorrectly handled certain VLAN
  packets. On some systems, a remote attacker could send specially crafted
  traffic to crash the system, leading to a denial of service.
  (CVE-2011-1576)

  Timo Warns discovered that the EFI GUID partition table was not correctly
  parsed. A physically local attacker that could insert mountable devices
  could exploit this to crash the system or possibly gain root privileges.
  (CVE-2011-1776)

  Dan Rosenberg discovered that the IPv4 diagnostic routines did not
  correctly validate certain requests. A local attacker could exploit this to
  consume CPU resources, leading to a denial of service. (CVE-2011-2213)

  Vasiliy Kulikov discovered that taskstats did not enforce access
  restrictions. A local attacker could exploit this to read certain
  information, leading to a loss of privacy. (CVE-2011-2494)

  Vasiliy Kulikov discovered that /proc/PID/io did not enforce access
  restrictions. A local attacker could exploit this to read certain
  information, leading to a loss of privacy. (CVE-2011-2495)

  Robert Swiecki discovered that mapping extensions were incorrectly handled.
  A local attacker could exploit this to crash the system, leading to a
  denial of service. (CVE-2011-2496)

  Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
  certain L2CAP requests. If a system was using Bluetooth, a remote attacker
  could send specially crafted traffic to crash the system or gain root
  privileges. (CVE-2011-2497)

  It was discovered that the wireless stack incorrectly verified SSID
  lengths. A local attacker could exploit this to cause a denial of service
  or gain root privileges. (CVE-2011-2517)

  Ben Pfaff discovered that Classless Queuing Disciplines (qdiscs) were being
  incorrectly handled. A local attacker could exploit this to crash the
  system, leading to a denial of service. (CVE-2011-2525)

  It was discovered that the EXT4 filesystem contained multiple off-by-one
  flaws. A local attacker could exploit this to crash the system, leading to
  a denial of service. (CVE-2011-2695)

  Herbert Xu discovered that certain fields were incorrectly handled when
  Generic Receive Offload (CVE-2011-2723)

  Christian Ohm discovered that the perf command looks for configuration
  files in the curre ...

  Description truncated, please see the referenced URL(s) for more information." );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.31-611-imx51", ver: "2.6.31-611.29", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

