if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843926" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2018-16880", "CVE-2018-18397", "CVE-2019-6133" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-16 15:29:00 +0000 (Thu, 16 May 2019)" );
	script_tag( name: "creation_date", value: "2019-03-07 04:11:55 +0100 (Thu, 07 Mar 2019)" );
	script_name( "Ubuntu Update for linux USN-3903-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.10" );
	script_xref( name: "USN", value: "3903-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3903-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'linux' package(s) announced via the USN-3903-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
  is present on the target host." );
	script_tag( name: "insight", value: "Jason Wang discovered that the vhost net
driver in the Linux kernel contained an out of bounds write vulnerability. An
attacker in a guest virtual machine could use this to cause a denial of service
(host system crash) or possibly execute arbitrary code in the host kernel.
(CVE-2018-16880)

Jann Horn discovered that the userfaultd implementation in the Linux kernel
did not properly restrict access to certain ioctls. A local attacker could
use this possibly to modify files. (CVE-2018-18397)

Jann Horn discovered a race condition in the fork() system call in the
Linux kernel. A local attacker could use this to gain access to services
that cache authorizations. (CVE-2019-6133)" );
	script_tag( name: "affected", value: "linux on Ubuntu 18.10." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.18.0-1007-gcp", ver: "4.18.0-1007.8", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.18.0-1008-kvm", ver: "4.18.0-1008.8", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.18.0-1010-raspi2", ver: "4.18.0-1010.12", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.18.0-1013-azure", ver: "4.18.0-1013.13", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.18.0-16-generic", ver: "4.18.0-16.17", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.18.0-16-generic-lpae", ver: "4.18.0-16.17", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.18.0-16-lowlatency", ver: "4.18.0-16.17", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.18.0-16-snapdragon", ver: "4.18.0-16.17", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-azure", ver: "4.18.0.1013.14", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "4.18.0.1007.7", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic", ver: "4.18.0.16.17", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "4.18.0.16.17", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gke", ver: "4.18.0.1007.7", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-kvm", ver: "4.18.0.1008.8", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "4.18.0.16.17", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-raspi2", ver: "4.18.0.1010.7", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-snapdragon", ver: "4.18.0.16.17", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

