if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1476-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841050" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-06-19 09:42:24 +0530 (Tue, 19 Jun 2012)" );
	script_cve_id( "CVE-2011-4131", "CVE-2012-2121", "CVE-2012-2133", "CVE-2012-2313", "CVE-2012-2319", "CVE-2012-2383", "CVE-2012-2384" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1476-1" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-1476-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1476-1" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Andy Adamson discovered a flaw in the Linux kernel's NFSv4 implementation.
  A remote NFS server (attacker) could exploit this flaw to cause a denial of
  service. (CVE-2011-4131)

  A flaw was discovered in the Linux kernel's KVM (kernel virtual machine).
  An administrative user in the guest OS could leverage this flaw to cause a
  denial of service in the host OS. (CVE-2012-2121)

  Schacher Raindel discovered a flaw in the Linux kernel's memory handling
  when hugetlb is enabled. An unprivileged local attacker could exploit this
  flaw to cause a denial of service and potentially gain higher privileges.
  (CVE-2012-2133)

  Stephan Mueller reported a flaw in the Linux kernel's dl2k network driver's
  handling of ioctls. An unprivileged local user could leverage this flaw to
  cause a denial of service. (CVE-2012-2313)

  Timo Warns reported multiple flaws in the Linux kernel's hfsplus
  filesystem. An unprivileged local user could exploit these flaws to gain
  root system privileges. (CVE-2012-2319)

  Xi Wang discovered a flaw in the Linux kernel's i915 graphics driver
  handling of cliprect on 32 bit systems. An unprivileged local attacker
  could leverage this flaw to cause a denial of service or potentially gain
  root privileges. (CVE-2012-2383)

  Xi Wang discovered a flaw in the Linux kernel's i915 graphics driver
  handling of buffer_count on 32 bit systems. An unprivileged local attacker
  could leverage this flaw to cause a denial of service or potentially gain
  root privileges. (CVE-2012-2384)" );
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
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-1211-omap4", ver: "3.0.0-1211.23", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

