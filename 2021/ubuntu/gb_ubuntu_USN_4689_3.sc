if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844795" );
	script_version( "2021-08-17T14:01:00+0000" );
	script_cve_id( "CVE-2021-1052", "CVE-2021-1053", "CVE-2021-1056" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-14 15:32:00 +0000 (Thu, 14 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-21 04:00:25 +0000 (Thu, 21 Jan 2021)" );
	script_name( "Ubuntu: Security Advisory for nvidia-graphics-drivers-418-server (USN-4689-3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "USN", value: "4689-3" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-January/005849.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nvidia-graphics-drivers-418-server'
  package(s) announced via the USN-4689-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the NVIDIA GPU display driver for the Linux kernel
contained a vulnerability that allowed user-mode clients to access legacy
privileged APIs. A local attacker could use this to cause a denial of
service or escalate privileges. (CVE-2021-1052)

It was discovered that the NVIDIA GPU display driver for the Linux kernel
did not properly validate a pointer received from userspace in some
situations. A local attacker could use this to cause a denial of service.
(CVE-2021-1053)

Xinyuan Lyu discovered that the NVIDIA GPU display driver for the Linux
kernel did not properly restrict device-level GPU isolation. A local
attacker could use this to cause a denial of service or possibly expose
sensitive information. (CVE-2021-1056)" );
	script_tag( name: "affected", value: "'nvidia-graphics-drivers-418-server' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-dkms-418-server", ver: "418.181.07-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-dkms-440-server", ver: "450.102.04-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-dkms-450-server", ver: "450.102.04-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-common-418-server", ver: "418.181.07-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-common-440-server", ver: "450.102.04-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-common-450-server", ver: "450.102.04-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-source-418-server", ver: "418.181.07-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-source-440-server", ver: "450.102.04-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-source-450-server", ver: "450.102.04-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-utils-418-server", ver: "418.181.07-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-utils-440-server", ver: "450.102.04-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-utils-450-server", ver: "450.102.04-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-418-server", ver: "418.181.07-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-440-server", ver: "450.102.04-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-450-server", ver: "450.102.04-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-dkms-418-server", ver: "418.181.07-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-dkms-440-server", ver: "450.102.04-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-dkms-450-server", ver: "450.102.04-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-common-418-server", ver: "418.181.07-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-common-440-server", ver: "450.102.04-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-common-450-server", ver: "450.102.04-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-source-418-server", ver: "418.181.07-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-source-440-server", ver: "450.102.04-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-source-450-server", ver: "450.102.04-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-utils-418-server", ver: "418.181.07-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-utils-440-server", ver: "450.102.04-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-utils-450-server", ver: "450.102.04-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-418-server", ver: "418.181.07-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-440-server", ver: "450.102.04-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-450-server", ver: "450.102.04-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU20.10"){
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-dkms-418-server", ver: "418.181.07-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-dkms-440-server", ver: "450.102.04-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-dkms-450-server", ver: "450.102.04-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-common-418-server", ver: "418.181.07-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-common-440-server", ver: "450.102.04-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-common-450-server", ver: "450.102.04-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-source-418-server", ver: "418.181.07-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-source-440-server", ver: "450.102.04-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-kernel-source-450-server", ver: "450.102.04-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-utils-418-server", ver: "418.181.07-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-utils-440-server", ver: "450.102.04-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "nvidia-utils-450-server", ver: "450.102.04-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-418-server", ver: "418.181.07-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-440-server", ver: "450.102.04-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-450-server", ver: "450.102.04-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
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

