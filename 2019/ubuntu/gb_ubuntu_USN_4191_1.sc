if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844237" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2019-12068", "CVE-2019-12155", "CVE-2019-13164", "CVE-2019-14378", "CVE-2019-15890" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-14 03:01:49 +0000 (Thu, 14 Nov 2019)" );
	script_name( "Ubuntu Update for qemu USN-4191-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.10|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4191-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-November/005208.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the USN-4191-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the LSI SCSI adapter emulator implementation in QEMU
did not properly validate executed scripts. A local attacker could use this
to cause a denial of service. (CVE-2019-12068)

Sergej Schumilo, Cornelius Aschermann and Simon Wörner discovered that the
qxl paravirtual graphics driver implementation in QEMU contained a null
pointer dereference. A local attacker in a guest could use this to cause a
denial of service. (CVE-2019-12155)

Riccardo Schirone discovered that the QEMU bridge helper did not properly
validate network interface names. A local attacker could possibly use this
to bypass ACL restrictions. (CVE-2019-13164)

It was discovered that a heap-based buffer overflow existed in the SLiRP
networking implementation of QEMU. A local attacker in a guest could use
this to cause a denial of service or possibly execute arbitrary code in the
host. (CVE-2019-14378)

It was discovered that a use-after-free vulnerability existed in the SLiRP
networking implementation of QEMU. A local attacker in a guest could use
this to cause a denial of service. (CVE-2019-15890)" );
	script_tag( name: "affected", value: "'qemu' package(s) on Ubuntu 19.10, Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:2.11+dfsg-1ubuntu7.20", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1:2.11+dfsg-1ubuntu7.20", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-common", ver: "1:2.11+dfsg-1ubuntu7.20", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.11+dfsg-1ubuntu7.20", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1:2.11+dfsg-1ubuntu7.20", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-utils", ver: "1:2.11+dfsg-1ubuntu7.20", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:4.0+dfsg-0ubuntu9.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1:4.0+dfsg-0ubuntu9.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-common", ver: "1:4.0+dfsg-0ubuntu9.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-gui", ver: "1:4.0+dfsg-0ubuntu9.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:4.0+dfsg-0ubuntu9.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1:4.0+dfsg-0ubuntu9.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-utils", ver: "1:4.0+dfsg-0ubuntu9.1", rls: "UBUNTU19.10" ) )){
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
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:3.1+dfsg-2ubuntu3.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1:3.1+dfsg-2ubuntu3.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-common", ver: "1:3.1+dfsg-2ubuntu3.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-gui", ver: "1:3.1+dfsg-2ubuntu3.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:3.1+dfsg-2ubuntu3.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1:3.1+dfsg-2ubuntu3.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-utils", ver: "1:3.1+dfsg-2ubuntu3.6", rls: "UBUNTU19.04" ) )){
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "qemu", ver: "1:2.5+dfsg-5ubuntu10.42", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1:2.5+dfsg-5ubuntu10.42", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-common", ver: "1:2.5+dfsg-5ubuntu10.42", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-system-x86", ver: "1:2.5+dfsg-5ubuntu10.42", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-user-static", ver: "1:2.5+dfsg-5ubuntu10.42", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "qemu-utils", ver: "1:2.5+dfsg-5ubuntu10.42", rls: "UBUNTU16.04 LTS" ) )){
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

