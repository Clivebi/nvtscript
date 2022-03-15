if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842185" );
	script_version( "2020-10-27T15:01:28+0000" );
	script_tag( name: "last_modification", value: "2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-05-01 05:50:13 +0200 (Fri, 01 May 2015)" );
	script_cve_id( "CVE-2015-2150", "CVE-2015-2666", "CVE-2015-2830", "CVE-2015-2922" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-2590-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Jan Beulich discovered the Xen virtual
machine subsystem of the Linux kernel did not properly restrict access to PCI
command registers. A local guest user could exploit this flaw to cause a denial
of service (host crash). (CVE-2015-2150)

A stack overflow was discovered in the microcode loader for the intel
x86 platform. A local attacker could exploit this flaw to cause a denial of
service (kernel crash) or to potentially execute code with kernel
privileges. (CVE-2015-2666)

A privilege escalation was discovered in the fork syscal vi the int80 entry
on 64 bit kernels with 32 bit emulation support. An unprivileged local
attacker could exploit this flaw to increase their privileges on the
system. (CVE-2015-2830)

It was discovered that the Linux kernel's IPv6 networking stack has a flaw
that allows using route advertisement (RA) messages to set the 'hop_limit'
to values that are too low. An unprivileged attacker on a local network
could exploit this flaw to cause a denial of service (IPv6 messages
dropped). (CVE-2015-2922)" );
	script_tag( name: "affected", value: "linux on Ubuntu 14.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2590-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2590-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.10" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-36-generic", ver: "3.16.0-36.48", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-36-generic-lpae", ver: "3.16.0-36.48", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-36-lowlatency", ver: "3.16.0-36.48", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-36-powerpc-e500mc", ver: "3.16.0-36.48", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-36-powerpc-smp", ver: "3.16.0-36.48", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-36-powerpc64-emb", ver: "3.16.0-36.48", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.16.0-36-powerpc64-smp", ver: "3.16.0-36.48", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

