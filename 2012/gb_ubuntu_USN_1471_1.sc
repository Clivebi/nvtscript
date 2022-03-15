if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1471-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841042" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-06-15 09:47:05 +0530 (Fri, 15 Jun 2012)" );
	script_cve_id( "CVE-2011-4131", "CVE-2012-2121", "CVE-2012-2133", "CVE-2012-2313", "CVE-2012-2319", "CVE-2012-2383", "CVE-2012-2384" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1471-1" );
	script_name( "Ubuntu Update for linux-lts-backport-oneiric USN-1471-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1471-1" );
	script_tag( name: "affected", value: "linux-lts-backport-oneiric on Ubuntu 10.04 LTS" );
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
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-21-generic", ver: "3.0.0-21.35~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-21-generic-pae", ver: "3.0.0-21.35~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-21-server", ver: "3.0.0-21.35~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-21-virtual", ver: "3.0.0-21.35~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

