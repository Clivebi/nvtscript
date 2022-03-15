if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1383-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840916" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-07 11:19:28 +0530 (Wed, 07 Mar 2012)" );
	script_cve_id( "CVE-2011-1927", "CVE-2011-1759", "CVE-2011-2182", "CVE-2011-2498", "CVE-2011-2518", "CVE-2011-3619" );
	script_xref( name: "USN", value: "1383-1" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-1383-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1383-1" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Aristide Fattori and Roberto Paleari reported a flaw in the Linux kernel's
  handling of IPv4 icmp packets. A remote user could exploit this to cause a
  denial of service. (CVE-2011-1927)

  Dan Rosenberg reported an error in the old ABI compatibility layer of ARM
  kernels. A local attacker could exploit this flaw to cause a denial of
  service or gain root privileges. (CVE-2011-1759)

  Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
  partitions. A local user could exploit this to cause a denial of service or
  escalate privileges. (CVE-2011-2182)

  The linux kernel did not properly account for PTE pages when deciding which
  task to kill in out of memory conditions. A local, unprivileged could
  exploit this flaw to cause a denial of service. (CVE-2011-2498)

  A flaw was discovered in the TOMOYO LSM's handling of mount system calls.
  An unprivileged user could oops the system causing a denial of service.
  (CVE-2011-2518)

  A flaw was discovered in the Linux kernel's AppArmor security interface
  when invalid information was written to it. An unprivileged local user
  could use this to cause a denial of service on the system. (CVE-2011-3619)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-1209-omap4", ver: "2.6.38-1209.22", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

