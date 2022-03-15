if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842160" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-09 07:09:08 +0200 (Thu, 09 Apr 2015)" );
	script_cve_id( "CVE-2015-1421", "CVE-2015-1465", "CVE-2015-1593", "CVE-2015-2041", "CVE-2015-2042" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-2563-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Sun Baoliang discovered a use after free
flaw in the Linux kernel's SCTP (Stream Control Transmission Protocol) subsystem
during INIT collisions. A remote attacker could exploit this flaw to cause a
denial of service (system crash) or potentially escalate their privileges on the
system. (CVE-2015-1421)

Marcelo Leitner discovered a flaw in the Linux kernel's routing of packets
to too many different dsts/too fast. A remote attacker can exploit this
flaw to cause a denial of service (system crash). (CVE-2015-1465)

An integer overflow was discovered in the stack randomization feature of
the Linux kernel on 64 bit platforms. A local attacker could exploit this
flaw to bypass the Address Space Layout Randomization (ASLR) mitigation
mechanism. (CVE-2015-1593)

An information leak was discovered in the Linux kernel's handling of
userspace configuration of the link layer control (LLC). A local user could
exploit this flaw to read data from other sysctl settings. (CVE-2015-2041)

An information leak was discovered in how the Linux kernel handles setting
the Reliable Datagram Sockets (RDS) settings. A local user could exploit
this flaw to read data from other sysctl settings. (CVE-2015-2042)" );
	script_tag( name: "affected", value: "linux on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2563-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2563-1/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-49-generic", ver: "3.13.0-49.81", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-49-generic-lpae", ver: "3.13.0-49.81", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-49-lowlatency", ver: "3.13.0-49.81", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-49-powerpc-e500", ver: "3.13.0-49.81", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-49-powerpc-e500mc", ver: "3.13.0-49.81", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-49-powerpc-smp", ver: "3.13.0-49.81", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-49-powerpc64-emb", ver: "3.13.0-49.81", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-49-powerpc64-smp", ver: "3.13.0-49.81", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

