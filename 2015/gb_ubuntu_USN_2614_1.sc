if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842211" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-09 11:05:38 +0200 (Tue, 09 Jun 2015)" );
	script_cve_id( "CVE-2014-9715", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-3331" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-2614-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Vincent Tondellier discovered an integer
overflow in the Linux kernel's netfilter connection tracking accounting of
loaded extensions. An attacker on the local area network (LAN) could potential
exploit this flaw to cause a denial of service (system crash of targeted system).
(CVE-2014-9715)

Jan Beulich discovered the Xen virtual machine subsystem of the Linux
kernel did not properly restrict access to PCI command registers. A local
guest user could exploit this flaw to cause a denial of service (host
crash). (CVE-2015-2150)

A privilege escalation was discovered in the fork syscal vi the int80 entry
on 64 bit kernels with 32 bit emulation support. An unprivileged local
attacker could exploit this flaw to increase their privileges on the
system. (CVE-2015-2830)

A memory corruption issue was discovered in AES decryption when using the
Intel AES-NI accelerated code path. A remote attacker could exploit this
flaw to cause a denial of service (system crash) or potentially escalate
privileges on Intel base machines with AEC-GCM mode IPSec security
association. (CVE-2015-3331)" );
	script_tag( name: "affected", value: "linux on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2614-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2614-1/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-53-generic", ver: "3.13.0-53.88", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-53-generic-lpae", ver: "3.13.0-53.88", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-53-lowlatency", ver: "3.13.0-53.88", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-53-powerpc-e500", ver: "3.13.0-53.88", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-53-powerpc-e500mc", ver: "3.13.0-53.88", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-53-powerpc-smp", ver: "3.13.0-53.88", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-53-powerpc64-emb", ver: "3.13.0-53.88", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-53-powerpc64-smp", ver: "3.13.0-53.88", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

