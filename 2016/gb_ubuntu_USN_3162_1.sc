if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842998" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-21 05:45:13 +0100 (Wed, 21 Dec 2016)" );
	script_cve_id( "CVE-2016-6213", "CVE-2016-8630", "CVE-2016-8633", "CVE-2016-8645", "CVE-2016-9313", "CVE-2016-9555" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-3162-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "CAI Qian discovered that shared bind mounts
  in a mount namespace exponentially added entries without restriction to the Linux
  kernel's mount table. A local attacker could use this to cause a denial of service
  (system crash). (CVE-2016-6213)

It was discovered that the KVM implementation for x86/x86_64 in the Linux
kernel could dereference a null pointer. An attacker in a guest virtual
machine could use this to cause a denial of service (system crash) in the
KVM host. (CVE-2016-8630)

Eyal Itkin discovered that the IP over IEEE 1394 (FireWire) implementation
in the Linux kernel contained a buffer overflow when handling fragmented
packets. A remote attacker could use this to possibly execute arbitrary
code with administrative privileges. (CVE-2016-8633)

Marco Grassi discovered that the TCP implementation in the Linux kernel
mishandles socket buffer (skb) truncation. A local attacker could use this
to cause a denial of service (system crash). (CVE-2016-8645)

It was discovered that the keyring implementation in the Linux kernel
improperly handled crypto registration in conjunction with successful key-
type registration. A local attacker could use this to cause a denial of
service (system crash). (CVE-2016-9313)

Andrey Konovalov discovered that the SCTP implementation in the Linux
kernel improperly handled validation of incoming data. A remote attacker
could use this to cause a denial of service (system crash). (CVE-2016-9555)" );
	script_tag( name: "affected", value: "linux on Ubuntu 16.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3162-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3162-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.10" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.8.0-32-generic", ver: "4.8.0-32.34", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.8.0-32-generic-lpae", ver: "4.8.0-32.34", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.8.0-32-lowlatency", ver: "4.8.0-32.34", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.8.0-32-powerpc-e500mc", ver: "4.8.0-32.34", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.8.0-32-powerpc-smp", ver: "4.8.0-32.34", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.8.0-32-powerpc64-emb", ver: "4.8.0-32.34", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic", ver: "4.8.0.32.41", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "4.8.0.32.41", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "4.8.0.32.41", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc", ver: "4.8.0.32.41", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-smp", ver: "4.8.0.32.41", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb", ver: "4.8.0.32.41", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

