if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1340-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840875" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-01-25 11:16:19 +0530 (Wed, 25 Jan 2012)" );
	script_cve_id( "CVE-2011-2203", "CVE-2011-4077", "CVE-2011-4110", "CVE-2011-4132", "CVE-2011-4330", "CVE-2012-0044" );
	script_xref( name: "USN", value: "1340-1" );
	script_name( "Ubuntu Update for linux-lts-backport-oneiric USN-1340-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1340-1" );
	script_tag( name: "affected", value: "linux-lts-backport-oneiric on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Clement Lecigne discovered a bug in the HFS filesystem. A local attacker
  could exploit this to cause a kernel oops. (CVE-2011-2203)

  A bug was discovered in the XFS filesystem's handling of pathnames. A local
  attacker could exploit this to crash the system, leading to a denial of
  service, or gain root privileges. (CVE-2011-4077)

  A flaw was found in how the Linux kernel handles user-defined key types. An
  unprivileged local user could exploit this to crash the system.
  (CVE-2011-4110)

  A flaw was found in the Journaling Block Device (JBD). A local attacker
  able to mount ext3 or ext4 file systems could exploit this to crash the
  system, leading to a denial of service. (CVE-2011-4132)

  Clement Lecigne discovered a bug in the HFS file system bounds checking.
  When a malformed HFS file system is mounted a local user could crash the
  system or gain root privileges. (CVE-2011-4330)

  Chen Haogang discovered an integer overflow that could result in memory
  corruption. A local unprivileged user could use this to crash the system.
  (CVE-2012-0044)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-15-generic", ver: "3.0.0-15.25~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-15-generic-pae", ver: "3.0.0-15.25~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-15-server", ver: "3.0.0-15.25~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-15-virtual", ver: "3.0.0-15.25~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

