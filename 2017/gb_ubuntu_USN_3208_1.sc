if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843061" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-22 15:14:45 +0100 (Wed, 22 Feb 2017)" );
	script_cve_id( "CVE-2016-10088", "CVE-2016-9191", "CVE-2016-9588", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5549", "CVE-2017-6074" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-19 01:29:00 +0000 (Thu, 19 Jul 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-3208-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the generic SCSI block layer in the Linux kernel did
not properly restrict write operations in certain situations. A local
attacker could use this to cause a denial of service (system crash) or
possibly gain administrative privileges. (CVE-2016-10088)

CAI Qian discovered that the sysctl implementation in the Linux kernel did
not properly perform reference counting in some situations. An unprivileged
attacker could use this to cause a denial of service (system hang).
(CVE-2016-9191)

Jim Mattson discovered that the KVM implementation in the Linux kernel
mismanages the #BP and #OF exceptions. A local attacker in a guest virtual
machine could use this to cause a denial of service (guest OS crash).
(CVE-2016-9588)

Andy Lutomirski and Willy Tarreau discovered that the KVM implementation in
the Linux kernel did not properly emulate instructions on the SS segment
register. A local attacker in a guest virtual machine could use this to
cause a denial of service (guest OS crash) or possibly gain administrative
privileges in the guest OS. (CVE-2017-2583)

Dmitry Vyukov discovered that the KVM implementation in the Linux kernel
improperly emulated certain instructions. A local attacker could use this
to obtain sensitive information (kernel memory). (CVE-2017-2584)

It was discovered that the KLSI KL5KUSB105 serial-to-USB device driver in
the Linux kernel did not properly initialize memory related to logging. A
local attacker could use this to expose sensitive information (kernel
memory). (CVE-2017-5549)

Andrey Konovalov discovered a use-after-free vulnerability in the DCCP
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly gain administrative
privileges. (CVE-2017-6074)" );
	script_tag( name: "affected", value: "linux on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3208-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3208-1/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1048-snapdragon", ver: "4.4.0-1048.52", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-64-generic", ver: "4.4.0-64.85", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-64-generic-lpae", ver: "4.4.0-64.85", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-64-lowlatency", ver: "4.4.0-64.85", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-64-powerpc-e500mc", ver: "4.4.0-64.85", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-64-powerpc-smp", ver: "4.4.0-64.85", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-64-powerpc64-emb", ver: "4.4.0-64.85", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-64-powerpc64-smp", ver: "4.4.0-64.85", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic", ver: "4.4.0.64.68", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "4.4.0.64.68", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "4.4.0.64.68", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc", ver: "4.4.0.64.68", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-smp", ver: "4.4.0.64.68", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb", ver: "4.4.0.64.68", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp", ver: "4.4.0.64.68", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-snapdragon", ver: "4.4.0.1048.40", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

