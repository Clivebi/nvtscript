if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842144" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-25 06:33:07 +0100 (Wed, 25 Mar 2015)" );
	script_cve_id( "CVE-2014-7822", "CVE-2014-9419", "CVE-2014-9683", "CVE-2015-1421" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-2541-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Linux kernel's splice system call did
not correctly validate its parameters. A local, unprivileged user could exploit
this flaw to cause a denial of service (system crash). (CVE-2014-7822)

A flaw was discovered in how Thread Local Storage (TLS) is handled by the
task switching function in the Linux kernel for x86_64 based machines. A
local user could exploit this flaw to bypass the Address Space Layout
Radomization (ASLR) protection mechanism. (CVE-2014-9419)

Dmitry Chernenkov discovered a buffer overflow in eCryptfs' encrypted file
name decoding. A local unprivileged user could exploit this flaw to cause a
denial of service (system crash) or potentially gain administrative
privileges. (CVE-2014-9683)

Sun Baoliang discovered a use after free flaw in the Linux kernel's SCTP
(Stream Control Transmission Protocol) subsystem during INIT collisions. A
remote attacker could exploit this flaw to cause a denial of service
(system crash) or potentially escalate their privileges on the system.
(CVE-2015-1421)" );
	script_tag( name: "affected", value: "linux on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2541-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2541-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-79-generic", ver: "3.2.0-79.115", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-79-generic-pae", ver: "3.2.0-79.115", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-79-highbank", ver: "3.2.0-79.115", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-79-omap", ver: "3.2.0-79.115", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-79-powerpc-smp", ver: "3.2.0-79.115", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-79-powerpc64-smp", ver: "3.2.0-79.115", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-79-virtual", ver: "3.2.0-79.115", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

