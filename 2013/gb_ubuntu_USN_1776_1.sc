if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1776-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841373" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-25 11:03:46 +0530 (Mon, 25 Mar 2013)" );
	script_cve_id( "CVE-2013-0268", "CVE-2013-0309", "CVE-2013-1773" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1776-1" );
	script_name( "Ubuntu Update for linux-ec2 USN-1776-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-ec2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "affected", value: "linux-ec2 on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A flaw was reported in the permission checks done by the Linux kernel for
  /dev/cpu/*/msr. A local root user with all capabilities dropped could
  exploit this flaw to execute code with full root capabilities.
  (CVE-2013-0268)

  A flaw was discovered in the Linux kernels handling of memory ranges with
  PROT_NONE when transparent hugepages are in use. An unprivileged local user
  could exploit this flaw to cause a denial of service (crash the system).
  (CVE-2013-0309)

  A flaw was discovered on the Linux kernel's VFAT filesystem driver when a
  disk is mounted with the utf8 option (this is the default on Ubuntu). On a
  system where disks/images can be auto-mounted or a FAT filesystem is
  mounted an unprivileged user can exploit the flaw to gain root privileges.
  (CVE-2013-1773)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-351-ec2", ver: "2.6.32-351.62", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

