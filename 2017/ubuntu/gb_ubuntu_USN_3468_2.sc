if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843352" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-01 05:01:44 +0100 (Wed, 01 Nov 2017)" );
	script_cve_id( "CVE-2017-1000252", "CVE-2017-10663", "CVE-2017-10911", "CVE-2017-11176", "CVE-2017-14340" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-23 17:53:00 +0000 (Wed, 23 Aug 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-hwe USN-3468-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-hwe'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3468-1 fixed vulnerabilities in the
  Linux kernel for Ubuntu 17.04. This update provides the corresponding updates
  for the Linux Hardware Enablement (HWE) kernel from Ubuntu 17.04 for Ubuntu
  16.04 LTS. It was discovered that the KVM subsystem in the Linux kernel did not
  properly bound guest IRQs. A local attacker in a guest VM could use this to
  cause a denial of service (host system crash). (CVE-2017-1000252) It was
  discovered that the Flash-Friendly File System (f2fs) implementation in the
  Linux kernel did not properly validate superblock metadata. A local attacker
  could use this to cause a denial of service (system crash) or possibly execute
  arbitrary code. (CVE-2017-10663) Anthony Perard discovered that the Xen virtual
  block driver did not properly initialize some data structures before passing
  them to user space. A local attacker in a guest VM could use this to expose
  sensitive information from the host OS or other guest VMs. (CVE-2017-10911) It
  was discovered that a use-after-free vulnerability existed in the POSIX message
  queue implementation in the Linux kernel. A local attacker could use this to
  cause a denial of service (system crash) or possibly execute arbitrary code.
  (CVE-2017-11176) Dave Chinner discovered that the XFS filesystem did not enforce
  that the realtime inode flag was settable only on filesystems on a realtime
  device. A local attacker could use this to cause a denial of service (system
  crash). (CVE-2017-14340)" );
	script_tag( name: "affected", value: "linux-hwe on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3468-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3468-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-38-generic", ver: "4.10.0-38.42~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-38-generic-lpae", ver: "4.10.0-38.42~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.10.0-38-lowlatency", ver: "4.10.0-38.42~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-hwe-16.04", ver: "4.10.0.38.40", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-hwe-16.04", ver: "4.10.0.38.40", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-hwe-16.04", ver: "4.10.0.38.40", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

