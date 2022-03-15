if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1384-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840922" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-07 11:20:07 +0530 (Wed, 07 Mar 2012)" );
	script_cve_id( "CVE-2011-4097", "CVE-2011-4127", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0055", "CVE-2012-0207" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-30 19:39:00 +0000 (Thu, 30 Jul 2020)" );
	script_xref( name: "USN", value: "1384-1" );
	script_name( "Ubuntu Update for linux-lts-backport-oneiric USN-1384-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1384-1" );
	script_tag( name: "affected", value: "linux-lts-backport-oneiric on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A bug was discovered in the Linux kernel's calculation of OOM (Out of
  memory) scores, that would result in the wrong process being killed. A user
  could use this to kill the process with the highest OOM score, even if that
  process belongs to another user or the system. (CVE-2011-4097)

  Paolo Bonzini discovered a flaw in Linux's handling of the SG_IO ioctl
  command. A local user, or user in a VM could exploit this flaw to bypass
  restrictions and gain read/write access to all data on the affected block
  device. (CVE-2011-4127)

  A flaw was found in KVM's Programmable Interval Timer (PIT). When a virtual
  interrupt control is not available a local user could use this to cause a
  denial of service by starting a timer. (CVE-2011-4622)

  A flaw was discovered in the XFS filesystem. If a local user mounts a
  specially crafted XFS image it could potential execute arbitrary code on
  the system. (CVE-2012-0038)

  Andy Whitcroft discovered a that the Overlayfs filesystem was not doing the
  extended permission checks needed by cgroups and Linux Security Modules
  (LSMs). A local user could exploit this to by-pass security policy and
  access files that should not be accessible. (CVE-2012-0055)

  A flaw was found in the linux kernels IPv4 IGMP query processing. A remote
  attacker could exploit this to cause a denial of service. (CVE-2012-0207)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-16-generic", ver: "3.0.0-16.29~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-16-generic-pae", ver: "3.0.0-16.29~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-16-server", ver: "3.0.0-16.29~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-16-virtual", ver: "3.0.0-16.29~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

