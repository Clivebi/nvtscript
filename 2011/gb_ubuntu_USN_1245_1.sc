if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1245-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840786" );
	script_version( "2020-08-04T07:16:50+0000" );
	script_tag( name: "last_modification", value: "2020-08-04 07:16:50 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-10-31 13:45:00 +0100 (Mon, 31 Oct 2011)" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1245-1" );
	script_cve_id( "CVE-2011-1576", "CVE-2011-1833", "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2497", "CVE-2011-2695", "CVE-2011-2699", "CVE-2011-2905", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191" );
	script_name( "Ubuntu Update for linux-mvl-dove USN-1245-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1245-1" );
	script_tag( name: "affected", value: "linux-mvl-dove on Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Ryan Sweat discovered that the kernel incorrectly handled certain VLAN
  packets. On some systems, a remote attacker could send specially crafted
  traffic to crash the system, leading to a denial of service.
  (CVE-2011-1576)

  Vasiliy Kulikov and Dan Rosenberg discovered that ecryptfs did not
  correctly check the origin of mount points. A local attacker could exploit
  this to trick the system into unmounting arbitrary mount points, leading to
  a denial of service. (CVE-2011-1833)

  Vasiliy Kulikov discovered that taskstats did not enforce access
  restrictions. A local attacker could exploit this to read certain
  information, leading to a loss of privacy. (CVE-2011-2494)

  Vasiliy Kulikov discovered that /proc/PID/io did not enforce access
  restrictions. A local attacker could exploit this to read certain
  information, leading to a loss of privacy. (CVE-2011-2495)

  Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
  certain L2CAP requests. If a system was using Bluetooth, a remote attacker
  could send specially crafted traffic to crash the system or gain root
  privileges. (CVE-2011-2497)

  It was discovered that the EXT4 filesystem contained multiple off-by-one
  flaws. A local attacker could exploit this to crash the system, leading to
  a denial of service. (CVE-2011-2695)

  Fernando Gont discovered that the IPv6 stack used predictable fragment
  identification numbers. A remote attacker could exploit this to exhaust
  network resources, leading to a denial of service. (CVE-2011-2699)

  Christian Ohm discovered that the perf command looks for configuration
  files in the current directory. If a privileged user were tricked into
  running perf in a directory containing a malicious configuration file, an
  attacker could run arbitrary commands and possibly gain privileges.
  (CVE-2011-2905)

  Time Warns discovered that long symlinks were incorrectly handled on Be
  filesystems. A local attacker could exploit this with a malformed Be
  filesystem and crash the system, leading to a denial of service.
  (CVE-2011-2928)

  Dan Kaminsky discovered that the kernel incorrectly handled random sequence
  number generation. An attacker could use this flaw to possibly predict
  sequence numbers and inject packets. (CVE-2011-3188)

  Darren Lavender discovered that the CIFS client incorrectly handled certain
  large values. A remote attacker with a malicious server could exploit this
  to crash the system or possibly execute arbitrary code as the root user.
  (CVE-2011-3191)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-419-dove", ver: "2.6.32-419.37", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

