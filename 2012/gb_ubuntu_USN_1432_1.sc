if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1432-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841001" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-08 12:37:31 +0530 (Tue, 08 May 2012)" );
	script_cve_id( "CVE-2011-4086", "CVE-2012-1090", "CVE-2012-2100" );
	script_xref( name: "USN", value: "1432-1" );
	script_name( "Ubuntu Update for linux USN-1432-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1432-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A flaw was found in the Linux's kernels ext4 file system when mounted with
  a journal. A local, unprivileged user could exploit this flaw to cause a
  denial of service. (CVE-2011-4086)

  A flaw was discovered in the Linux kernel's cifs file system. An
  unprivileged local user could exploit this flaw to crash the system leading
  to a denial of service. (CVE-2012-1090)

  A flaw was found in the Linux kernel's ext4 file system when mounting a
  corrupt filesystem. A user-assisted remote attacker could exploit this flaw
  to cause a denial of service. (CVE-2012-2100)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-generic", ver: "2.6.38-15.59", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-generic-pae", ver: "2.6.38-15.59", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-omap", ver: "2.6.38-15.59", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-powerpc", ver: "2.6.38-15.59", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-powerpc-smp", ver: "2.6.38-15.59", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-powerpc64-smp", ver: "2.6.38-15.59", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-server", ver: "2.6.38-15.59", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-versatile", ver: "2.6.38-15.59", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.38-15-virtual", ver: "2.6.38-15.59", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

