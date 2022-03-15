if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844462" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2020-0067", "CVE-2020-0543", "CVE-2020-12114", "CVE-2020-12464", "CVE-2020-12659", "CVE-2020-1749" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-22 22:15:00 +0000 (Mon, 22 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-10 03:01:36 +0000 (Wed, 10 Jun 2020)" );
	script_name( "Ubuntu: Security Advisory for linux-gke-5.0 (USN-4388-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "4388-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-June/005470.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-gke-5.0'
  package(s) announced via the USN-4388-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the F2FS file system implementation in the Linux
kernel did not properly perform bounds checking on xattrs in some
situations. A local attacker could possibly use this to expose sensitive
information (kernel memory). (CVE-2020-0067)

It was discovered that memory contents previously stored in
microarchitectural special registers after RDRAND, RDSEED, and SGX EGETKEY
read operations on Intel client and Xeon E3 processors may be briefly
exposed to processes on the same or different processor cores. A local
attacker could use this to expose sensitive information. (CVE-2020-0543)

Piotr Krysiuk discovered that race conditions existed in the file system
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash). (CVE-2020-12114)

It was discovered that the USB susbsystem's scatter-gather implementation
in the Linux kernel did not properly take data references in some
situations, leading to a use-after-free. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2020-12464)

Bui Quang Minh discovered that the XDP socket implementation in the Linux
kernel did not properly validate meta-data passed from user space, leading
to an out-of-bounds write vulnerability. A local attacker with the
CAP_NET_ADMIN capability could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2020-12659)

Xiumei Mu discovered that the IPSec implementation in the Linux kernel did
not properly encrypt IPv6 traffic in some situations. An attacker could use
this to expose sensitive information. (CVE-2020-1749)" );
	script_tag( name: "affected", value: "'linux-gke-5.0' package(s) on Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1042-gke", ver: "5.0.0-1042.43", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1059-oem-osp1", ver: "5.0.0-1059.64", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke-5.0", ver: "5.0.0.1042.27", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oem-osp1", ver: "5.0.0.1059.58", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "Please", ver: "note that the mitigation for CVE-2020-0543 requires a processor", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "or", ver: "via the intel-microcode package. The kernel update for this issue", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "vulnerability", ver: "status.", rls: "UBUNTU18.04 LTS" ) )){
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

