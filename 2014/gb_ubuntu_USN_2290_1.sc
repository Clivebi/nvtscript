if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841897" );
	script_version( "2020-08-18T09:42:52+0000" );
	script_tag( name: "last_modification", value: "2020-08-18 09:42:52 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-07-21 16:55:37 +0530 (Mon, 21 Jul 2014)" );
	script_cve_id( "CVE-2014-4943", "CVE-2014-1739", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3940", "CVE-2014-4608", "CVE-2014-4611" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for linux USN-2290-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 14.04 LTS" );
	script_tag( name: "insight", value: "Sasha Levin reported a flaw in the Linux kernel's
point-to-point protocol (PPP) when used with the Layer Two Tunneling Protocol
(L2TP). A local user could exploit this flaw to gain administrative privileges.
(CVE-2014-4943)

Salva Peir&#243  discovered an information leak in the Linux kernel's media-
device driver. A local attacker could exploit this flaw to obtain sensitive
information from kernel memory. (CVE-2014-1739)

A bounds check error was discovered in the socket filter subsystem of the
Linux kernel. A local user could exploit this flaw to cause a denial of
service (system crash) via crafted BPF instructions. (CVE-2014-3144)

A remainder calculation error was discovered in the socket filter subsystem
of the Linux kernel. A local user could exploit this flaw to cause a denial
of service (system crash) via crafted BPF instructions. (CVE-2014-3145)

A flaw was discovered in the Linux kernel's handling of hugetlb entries. A
local user could exploit this flaw to cause a denial service (memory
corruption or system crash). (CVE-2014-3940)

Don Bailey discovered a flaw in the LZO decompress algorithm used by the
Linux kernel. An attacker could exploit this flaw to cause a denial of
service (memory corruption or OOPS). (CVE-2014-4608)

Don Bailey and Ludvig Strigeus discovered an integer overflow in the Linux
kernel's implementation of the LZ4 decompression algorithm, when used by
code not complying with API limitations. An attacker could exploit this
flaw to cause a denial of service (memory corruption) or possibly other
unspecified impact. (CVE-2014-4611)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2290-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2290-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-32-generic", ver: "3.13.0-32.57", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-32-generic-lpae", ver: "3.13.0-32.57", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-32-lowlatency", ver: "3.13.0-32.57", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-32-powerpc-e500", ver: "3.13.0-32.57", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-32-powerpc-e500mc", ver: "3.13.0-32.57", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-32-powerpc-smp", ver: "3.13.0-32.57", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-32-powerpc64-emb", ver: "3.13.0-32.57", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-32-powerpc64-smp", ver: "3.13.0-32.57", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

