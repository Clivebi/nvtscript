if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844601" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2019-12211", "CVE-2019-12213" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-03 05:15:00 +0000 (Sat, 03 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-09-23 03:00:24 +0000 (Wed, 23 Sep 2020)" );
	script_name( "Ubuntu: Security Advisory for freeimage (USN-4529-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "4529-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005639.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freeimage'
  package(s) announced via the USN-4529-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that FreeImage incorrectly handled certain memory
operations. If a user were tricked into opening a crafted TIFF file, a
remote attacker could use this issue to cause a heap buffer overflow,
resulting in a denial of service attack. (CVE-2019-12211)

It was discovered that FreeImage incorrectly processed images under
certain circumstances. If a user were tricked into opening a crafted
TIFF file, a remote attacker could possibly use this issue to cause a
stack exhaustion condition, resulting in a denial of service attack.
(CVE-2019-12213)" );
	script_tag( name: "affected", value: "'freeimage' package(s) on Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libfreeimage-dev", ver: "3.17.0+ds1-5+deb9u1build0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libfreeimage3", ver: "3.17.0+ds1-5+deb9u1build0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libfreeimageplus-dev", ver: "3.17.0+ds1-5+deb9u1build0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libfreeimageplus3", ver: "3.17.0+ds1-5+deb9u1build0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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

