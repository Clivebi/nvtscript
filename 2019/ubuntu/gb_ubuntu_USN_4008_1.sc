if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844037" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2019-11190", "CVE-2019-11810", "CVE-2019-11815", "CVE-2019-11191" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-02 15:25:00 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-06-05 02:00:35 +0000 (Wed, 05 Jun 2019)" );
	script_name( "Ubuntu Update for linux USN-4008-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4008-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-June/004939.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the USN-4008-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Robert wicki discovered that the Linux kernel did not properly apply
Address Space Layout Randomization (ASLR) in some situations for setuid elf
binaries. A local attacker could use this to improve the chances of
exploiting an existing vulnerability in a setuid elf binary.
(CVE-2019-11190)

It was discovered that a null pointer dereference vulnerability existed in
the LSI Logic MegaRAID driver in the Linux kernel. A local attacker could
use this to cause a denial of service (system crash). (CVE-2019-11810)

It was discovered that a race condition leading to a use-after-free existed
in the Reliable Datagram Sockets (RDS) protocol implementation in the Linux
kernel. The RDS protocol is blacklisted by default in Ubuntu. If enabled, a
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2019-11815)

Federico Manuel Bento discovered that the Linux kernel did not properly
apply Address Space Layout Randomization (ASLR) in some situations for
setuid a.out binaries. A local attacker could use this to improve the
chances of exploiting an existing vulnerability in a setuid a.out binary.
(CVE-2019-11191)

As a hardening measure, this update disables a.out support." );
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
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1047-kvm", ver: "4.4.0-1047.53", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1084-aws", ver: "4.4.0-1084.94", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1110-raspi2", ver: "4.4.0-1110.118", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-1114-snapdragon", ver: "4.4.0-1114.119", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-150-generic", ver: "4.4.0-150.176", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-150-generic-lpae", ver: "4.4.0-150.176", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-150-lowlatency", ver: "4.4.0-150.176", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-150-powerpc-e500mc", ver: "4.4.0-150.176", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-150-powerpc-smp", ver: "4.4.0-150.176", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-150-powerpc64-emb", ver: "4.4.0-150.176", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.4.0-150-powerpc64-smp", ver: "4.4.0-150.176", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-aws", ver: "4.4.0.1084.87", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic", ver: "4.4.0.150.158", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "4.4.0.150.158", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-kvm", ver: "4.4.0.1047.47", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "4.4.0.150.158", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc", ver: "4.4.0.150.158", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc-smp", ver: "4.4.0.150.158", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb", ver: "4.4.0.150.158", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp", ver: "4.4.0.150.158", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-raspi2", ver: "4.4.0.1110.110", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-snapdragon", ver: "4.4.0.1114.106", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual", ver: "4.4.0.150.158", rls: "UBUNTU16.04 LTS" ) )){
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

