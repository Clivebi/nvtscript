if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1455-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841024" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-06-01 09:54:04 +0530 (Fri, 01 Jun 2012)" );
	script_cve_id( "CVE-2012-1601", "CVE-2012-2123" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1455-1" );
	script_name( "Ubuntu Update for linux-lts-backport-oneiric USN-1455-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1455-1" );
	script_tag( name: "affected", value: "linux-lts-backport-oneiric on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A flaw was found in the Linux kernel's KVM (Kernel Virtual Machine) virtual
  cpu setup. An unprivileged local user could exploit this flaw to crash the
  system leading to a denial of service. (CVE-2012-1601)

  Steve Grubb reported a flaw with Linux fscaps (file system base
  capabilities) when used to increase the permissions of a process. For
  application on which fscaps are in use a local attacker can disable address
  space randomization to make attacking the process with raised privileges
  easier. (CVE-2012-2123)" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-20-generic", ver: "3.0.0-20.34~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-20-generic-pae", ver: "3.0.0-20.34~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-20-server", ver: "3.0.0-20.34~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-20-virtual", ver: "3.0.0-20.34~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

