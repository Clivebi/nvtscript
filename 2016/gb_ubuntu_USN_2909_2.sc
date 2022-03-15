if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842668" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-02-28 06:27:27 +0100 (Sun, 28 Feb 2016)" );
	script_cve_id( "CVE-2016-1576", "CVE-2016-1575", "CVE-2015-8785" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-lts-utopic USN-2909-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-utopic'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2909-1 fixed vulnerabilities in
  the Ubuntu 14.10 Linux kernel backported to Ubuntu 14.04 LTS. An incorrect
  locking fix caused a regression that broke graphics displays for Ubuntu
  14.04 LTS guests running the Ubuntu 14.10 backport kernel within VMWare
  virtual machines. This update fixes the problem.

  We apologize for the inconvenience.

  Original advisory details:

  halfdog discovered that OverlayFS, when mounting on top of a FUSE mount,
  incorrectly propagated file attributes, including setuid. A local
  unprivileged attacker could use this to gain privileges. (CVE-2016-1576)

  halfdog discovered that OverlayFS in the Linux kernel incorrectly
  propagated security sensitive extended attributes, such as POSIX ACLs. A
  local unprivileged attacker could use this to gain privileges.
  (CVE-2016-1575)

  It was discovered that the Linux kernel's Filesystem in Userspace (FUSE)
  implementation did not handle initial zero length segments properly. A
  local attacker could use this to cause a denial of service (unkillable
  task). (CVE-2015-8785)" );
	script_tag( name: "affected", value: "linux-lts-utopic on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2909-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2909-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-62-generic", ver: "3.16.0-62.83~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-62-generic-lpae", ver: "3.16.0-62.83~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-62-lowlatency", ver: "3.16.0-62.83~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-62-powerpc-e500mc", ver: "3.16.0-62.83~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-62-powerpc-smp", ver: "3.16.0-62.83~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-62-powerpc64-emb", ver: "3.16.0-62.83~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-62-powerpc64-smp", ver: "3.16.0-62.83~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

