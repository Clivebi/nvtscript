if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.845005" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2021-1093", "CVE-2021-1094", "CVE-2021-1095" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-30 18:26:00 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-21 03:01:01 +0000 (Wed, 21 Jul 2021)" );
	script_name( "Ubuntu: Security Advisory for nvidia-graphics-drivers-390 (USN-5019-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-5019-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-July/006113.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nvidia-graphics-drivers-390'
  package(s) announced via the USN-5019-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that an assert() could be triggered in the NVIDIA
graphics drivers. A local attacker could use this to cause a denial
of service. (CVE-2021-1093)

It was discovered that the NVIDIA graphics drivers permitted an
out-of-bounds array access. A local attacker could use this
to cause a denial of service or possibly expose sensitive
information. (CVE-2021-1094)

It was discovered that the NVIDIA graphics drivers contained a
vulnerability in the kernel mode layer where they did not properly
control calls with embedded parameters in some situations. A local
attacker could use this to cause a denial of service.  (CVE-2021-1095)" );
	script_tag( name: "affected", value: "'nvidia-graphics-drivers-390' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-390", ver: "390.144-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-418-server", ver: "418.211.00-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-440-server", ver: "450.142.00-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-450", ver: "460.91.03-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-450-server", ver: "450.142.00-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-455", ver: "460.91.03-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-460", ver: "460.91.03-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-460-server", ver: "460.91.03-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-465", ver: "470.57.02-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-470", ver: "470.57.02-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-390", ver: "390.144-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-418-server", ver: "418.211.00-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-440-server", ver: "450.142.00-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-450", ver: "460.91.03-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-450-server", ver: "450.142.00-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-455", ver: "460.91.03-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-460", ver: "460.91.03-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-460-server", ver: "460.91.03-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-465", ver: "470.57.02-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-470", ver: "470.57.02-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-390", ver: "390.144-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-418-server", ver: "418.211.00-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-440-server", ver: "450.142.00-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-450", ver: "460.91.03-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-450-server", ver: "450.142.00-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-455", ver: "460.91.03-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-460", ver: "460.91.03-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-460-server", ver: "460.91.03-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-465", ver: "470.57.02-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-video-nvidia-470", ver: "470.57.02-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
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
