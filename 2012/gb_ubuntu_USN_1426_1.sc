if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1426-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840990" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 20:14:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "creation_date", value: "2012-04-26 10:36:27 +0530 (Thu, 26 Apr 2012)" );
	script_cve_id( "CVE-2011-4347", "CVE-2012-0045", "CVE-2012-1090", "CVE-2012-1097" );
	script_xref( name: "USN", value: "1426-1" );
	script_name( "Ubuntu Update for linux-ec2 USN-1426-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1426-1" );
	script_tag( name: "affected", value: "linux-ec2 on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Sasha Levin discovered a flaw in the permission checking for device
  assignments requested via the kvm ioctl in the Linux kernel. A local user
  could use this flaw to crash the system causing a denial of service.
  (CVE-2011-4347)

  Stephan Baerwolf discovered a flaw in the KVM (kernel-based virtual
  machine) subsystem of the Linux kernel. A local unprivileged user can crash
  use this flaw to crash VMs causing a deny of service. (CVE-2012-0045)

  A flaw was discovered in the Linux kernel's cifs file system. An
  unprivileged local user could exploit this flaw to crash the system leading
  to a denial of service. (CVE-2012-1090)

  H. Peter Anvin reported a flaw in the Linux kernel that could crash the
  system. A local user could exploit this flaw to crash the system.
  (CVE-2012-1097)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-345-ec2", ver: "2.6.32-345.47", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

