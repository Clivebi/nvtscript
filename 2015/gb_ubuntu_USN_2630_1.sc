if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842235" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-11 06:30:50 +0200 (Thu, 11 Jun 2015)" );
	script_cve_id( "CVE-2015-3209", "CVE-2015-4037", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for qemu USN-2630-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Matt Tait discovered that QEMU incorrectly
handled the virtual PCNET driver. A malicious guest could use this issue to
cause a denial of service, or possibly execute arbitrary code on the host as the
user running the QEMU process. In the default installation, when QEMU is used
with libvirt, attackers would be isolated by the libvirt AppArmor profile.
(CVE-2015-3209)

Kurt Seifried discovered that QEMU incorrectly handled certain temporary
files. A local attacker could use this issue to cause a denial of service.
(CVE-2015-4037)

Jan Beulich discovered that the QEMU Xen code incorrectly restricted write
access to the host MSI message data field. A malicious guest could use this
issue to cause a denial of service. This issue only applied to Ubuntu 14.04
LTS, Ubuntu 14.10 and Ubuntu 15.04. (CVE-2015-4103)

Jan Beulich discovered that the QEMU Xen code incorrectly restricted access
to the PCI MSI mask bits. A malicious guest could use this issue to cause a
denial of service. This issue only applied to Ubuntu 14.04 LTS, Ubuntu
14.10 and Ubuntu 15.04. (CVE-2015-4104)

Jan Beulich discovered that the QEMU Xen code incorrectly handled MSI-X
error messages. A malicious guest could use this issue to cause a denial of
service. This issue only applied to Ubuntu 14.04 LTS, Ubuntu 14.10 and
Ubuntu 15.04. (CVE-2015-4105)

Jan Beulich discovered that the QEMU Xen code incorrectly restricted write
access to the PCI config space. A malicious guest could use this issue to
cause a denial of service, obtain sensitive information, or possibly
execute arbitrary code. This issue only applied to Ubuntu 14.04 LTS,
Ubuntu 14.10 and Ubuntu 15.04. (CVE-2015-4106)" );
	script_tag( name: "affected", value: "qemu on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2630-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2630-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "2.1+dfsg-4ubuntu6.7", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "2.1+dfsg-4ubuntu6.7", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "2.1+dfsg-4ubuntu6.7", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "2.1+dfsg-4ubuntu6.7", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "2.1+dfsg-4ubuntu6.7", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "2.1+dfsg-4ubuntu6.7", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "2.1+dfsg-4ubuntu6.7", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "2.1+dfsg-4ubuntu6.7", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "qemu-system", ver: "2.0.0+dfsg-2ubuntu1.13", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-aarch64", ver: "2.0.0+dfsg-2ubuntu1.13", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-arm", ver: "2.0.0+dfsg-2ubuntu1.13", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-mips", ver: "2.0.0+dfsg-2ubuntu1.13", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-misc", ver: "2.0.0+dfsg-2ubuntu1.13", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-ppc", ver: "2.0.0+dfsg-2ubuntu1.13", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-sparc", ver: "2.0.0+dfsg-2ubuntu1.13", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "2.0.0+dfsg-2ubuntu1.13", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1.0+noroms-0ubuntu14.23", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

