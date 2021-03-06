if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842035" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-11-14 06:46:51 +0100 (Fri, 14 Nov 2014)" );
	script_cve_id( "CVE-2014-3615", "CVE-2014-3640", "CVE-2014-3689", "CVE-2014-5263", "CVE-2014-5388", "CVE-2014-7815" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for qemu USN-2409-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Laszlo Ersek discovered that QEMU incorrectly
handled memory in the vga device. A malicious guest could possibly use this issue
to read arbitrary host memory. This issue only affected Ubuntu 14.04 LTS and Ubuntu
14.10. (CVE-2014-3615)

Xavier Mehrenberger and Stephane Duverger discovered that QEMU incorrectly
handled certain udp packets when using guest networking. A malicious guest
could possibly use this issue to cause a denial of service. (CVE-2014-3640)

It was discovered that QEMU incorrectly handled parameter validation in
the vmware_vga device. A malicious guest could possibly use this issue to
write into memory of the host, leading to privilege escalation.
(CVE-2014-3689)

It was discovered that QEMU incorrectly handled USB xHCI controller live
migration. An attacker could possibly use this issue to cause a denial of
service, or possibly execute arbitrary code. This issue only affected
Ubuntu 14.04 LTS. (CVE-2014-5263)

Michael S. Tsirkin discovered that QEMU incorrectly handled memory in the
ACPI PCI hotplug interface. A malicious guest could possibly use this issue
to access memory of the host, leading to information disclosure or
privilege escalation. This issue only affected Ubuntu 14.04 LTS.
(CVE-2014-5388)

James Spadaro discovered that QEMU incorrectly handled certain VNC
bytes_per_pixel values. An attacker having access to a VNC console could
possibly use this issue to cause a guest to crash, resulting in a denial of
service. (CVE-2014-7815)" );
	script_tag( name: "affected", value: "qemu on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2409-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2409-1/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS|12\\.04 LTS|10\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "2.1+dfsg-4ubuntu6.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "2.1+dfsg-4ubuntu6.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "2.1+dfsg-4ubuntu6.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "2.1+dfsg-4ubuntu6.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "2.1+dfsg-4ubuntu6.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "2.1+dfsg-4ubuntu6.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "2.1+dfsg-4ubuntu6.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "2.1+dfsg-4ubuntu6.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "2.0.0+dfsg-2ubuntu1.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "2.0.0+dfsg-2ubuntu1.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "2.0.0+dfsg-2ubuntu1.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "2.0.0+dfsg-2ubuntu1.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "2.0.0+dfsg-2ubuntu1.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "2.0.0+dfsg-2ubuntu1.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "2.0.0+dfsg-2ubuntu1.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "2.0.0+dfsg-2ubuntu1.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1.0+noroms-0ubuntu14.19", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "0.12.3+noroms-0ubuntu9.25", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

