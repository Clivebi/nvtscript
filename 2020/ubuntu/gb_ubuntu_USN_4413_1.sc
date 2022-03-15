if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844485" );
	script_version( "2021-07-12T11:00:45+0000" );
	script_cve_id( "CVE-2020-10711", "CVE-2020-12770", "CVE-2020-13143", "CVE-2020-10751", "CVE-2020-12768" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 11:00:45 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-29 19:15:00 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-03 03:01:43 +0000 (Fri, 03 Jul 2020)" );
	script_name( "Ubuntu: Security Advisory for linux-gke-5.0 (USN-4413-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "4413-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-July/005501.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-gke-5.0'
  package(s) announced via the USN-4413-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Matthew Sheets discovered that the SELinux network label handling
implementation in the Linux kernel could be coerced into de-referencing a
NULL pointer. A remote attacker could use this to cause a denial of service
(system crash). (CVE-2020-10711)

It was discovered that the SCSI generic (sg) driver in the Linux kernel did
not properly handle certain error conditions correctly. A local privileged
attacker could use this to cause a denial of service (system crash).
(CVE-2020-12770)

It was discovered that the USB Gadget device driver in the Linux kernel did
not validate arguments passed from configfs in some situations. A local
attacker could possibly use this to cause a denial of service (system
crash) or possibly expose sensitive information. (CVE-2020-13143)

Dmitry Vyukov discovered that the SELinux netlink security hook in the
Linux kernel did not validate messages in some situations. A privileged
attacker could use this to bypass SELinux netlink restrictions.
(CVE-2020-10751)

It was discovered that the KVM implementation in the Linux kernel did not
properly deallocate memory on initialization for some processors. A local
attacker could possibly use this to cause a denial of service.
(CVE-2020-12768)" );
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
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1043-gke", ver: "5.0.0-1043.44", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1063-oem-osp1", ver: "5.0.0-1063.68", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke-5.0", ver: "5.0.0.1043.28", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oem-osp1", ver: "5.0.0.1063.61", rls: "UBUNTU18.04 LTS" ) )){
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

