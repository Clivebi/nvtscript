if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844303" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_cve_id( "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-28 21:15:00 +0000 (Tue, 28 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-01-23 04:00:20 +0000 (Thu, 23 Jan 2020)" );
	script_name( "Ubuntu Update for zlib USN-4246-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4246-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-January/005284.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zlib'
  package(s) announced via the USN-4246-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that zlib incorrectly handled pointer arithmetic. An
attacker
could use this issue to cause zlib to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2016-9840, CVE-2016-9841)

It was discovered that zlib incorrectly handled vectors involving left
shifts of
negative integers. An attacker could use this issue to cause zlib to
crash, resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2016-9842)

It was discovered that zlib incorrectly handled vectors involving
big-endian CRC
calculation. An attacker could use this issue to cause zlib to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2016-9843)" );
	script_tag( name: "affected", value: "'zlib' package(s) on Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "lib32z1", ver: "1:1.2.8.dfsg-2ubuntu4.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "lib64z1", ver: "1:1.2.8.dfsg-2ubuntu4.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libn32z1", ver: "1:1.2.8.dfsg-2ubuntu4.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libx32z1", ver: "1:1.2.8.dfsg-2ubuntu4.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "zlib1g", ver: "1:1.2.8.dfsg-2ubuntu4.3", rls: "UBUNTU16.04 LTS" ) )){
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

