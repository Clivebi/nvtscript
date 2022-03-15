if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844411" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_cve_id( "CVE-2019-16233", "CVE-2019-16234", "CVE-2019-19768", "CVE-2020-8648", "CVE-2020-9383" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-10 20:15:00 +0000 (Wed, 10 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-04-29 03:01:18 +0000 (Wed, 29 Apr 2020)" );
	script_name( "Ubuntu: Security Advisory for linux (USN-4346-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4346-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-April/005411.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the USN-4346-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the QLogic Fibre Channel driver in the Linux kernel
did not properly check for error, leading to a NULL pointer dereference. A
local attacker could possibly use this to cause a denial of service (system
crash). (CVE-2019-16233)

It was discovered that the Intel Wi-Fi driver in the Linux kernel did not
properly check for errors in some situations. A local attacker could
possibly use this to cause a denial of service (system crash).
(CVE-2019-16234)

Tristan Madani discovered that the block I/O tracing implementation in the
Linux kernel contained a race condition. A local attacker could use this to
cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2019-19768)

It was discovered that the virtual terminal implementation in the Linux
kernel contained a race condition. A local attacker could possibly use this
to cause a denial of service (system crash) or expose sensitive
information. (CVE-2020-8648)

Jordy Zomer discovered that the floppy driver in the Linux kernel did not
properly check for errors in some situations. A local attacker could
possibly use this to cause a denial of service (system crash) or possibly
expose sensitive information. (CVE-2020-9383)" );
	script_tag( name: "affected", value: "'linux' package(s) on Ubuntu 16.04 LTS." );
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
report = "";
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1070-kvm", ver: "4.4.0-1070.77", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1106-aws", ver: "4.4.0-1106.117", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1132-raspi2", ver: "4.4.0-1132.141", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1136-snapdragon", ver: "4.4.0-1136.144", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-178-generic", ver: "4.4.0-178.208", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-178-generic-lpae", ver: "4.4.0-178.208", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-178-lowlatency", ver: "4.4.0-178.208", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-178-powerpc-e500mc", ver: "4.4.0-178.208", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-178-powerpc-smp", ver: "4.4.0-178.208", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-178-powerpc64-emb", ver: "4.4.0-178.208", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-178-powerpc64-smp", ver: "4.4.0-178.208", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-aws", ver: "4.4.0.1106.110", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic", ver: "4.4.0.178.186", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "4.4.0.178.186", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-kvm", ver: "4.4.0.1070.70", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "4.4.0.178.186", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc", ver: "4.4.0.178.186", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc-smp", ver: "4.4.0.178.186", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb", ver: "4.4.0.178.186", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp", ver: "4.4.0.178.186", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-raspi2", ver: "4.4.0.1132.132", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-snapdragon", ver: "4.4.0.1136.128", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual", ver: "4.4.0.178.186", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

