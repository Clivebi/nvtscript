if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842571" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-18 05:44:39 +0100 (Fri, 18 Dec 2015)" );
	script_cve_id( "CVE-2015-8104", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7884", "CVE-2015-7885" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-lts-wily USN-2843-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-wily'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Jan Beulich discovered that the KVM svm
hypervisor implementation in the Linux kernel did not properly catch Debug
exceptions on AMD processors. An attacker in a guest virtual machine could use
this to cause a denial of service (system crash) in the host OS. (CVE-2015-8104)

&#37101 &#27704 &#21018  discovered that the ppp implementation in the Linux kernel
did not ensure that certain slot numbers are valid. A local attacker with the
privilege to call ioctl() on /dev/ppp could cause a denial of service
(system crash). (CVE-2015-7799)

Dmitry Vyukov discovered that the Linux kernel's keyring handler attempted
to garbage collect incompletely instantiated keys. A local unprivileged
attacker could use this to cause a denial of service (system crash).
(CVE-2015-7872)

It was discovered that the virtual video osd test driver in the Linux
kernel did not properly initialize data structures. A local attacker could
use this to obtain sensitive information from the kernel. (CVE-2015-7884)

It was discovered that the driver for Digi Neo and ClassicBoard devices did
not properly initialize data structures. A local attacker could use this to
obtain sensitive information from the kernel. (CVE-2015-7885)" );
	script_tag( name: "affected", value: "linux-lts-wily on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2843-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2843-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-21-generic", ver: "4.2.0-21.25~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-21-generic-lpae", ver: "4.2.0-21.25~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-21-lowlatency", ver: "4.2.0-21.25~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-21-powerpc-e500mc", ver: "4.2.0-21.25~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-21-powerpc-smp", ver: "4.2.0-21.25~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-21-powerpc64-emb", ver: "4.2.0-21.25~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-21-powerpc64-smp", ver: "4.2.0-21.25~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

