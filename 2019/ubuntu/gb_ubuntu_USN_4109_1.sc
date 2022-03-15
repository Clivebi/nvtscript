if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844149" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2017-17480", "CVE-2018-14423", "CVE-2018-18088", "CVE-2018-5785", "CVE-2018-6616" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-03 16:07:00 +0000 (Wed, 03 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-08-22 02:01:04 +0000 (Thu, 22 Aug 2019)" );
	script_name( "Ubuntu Update for openjpeg2 USN-4109-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "4109-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-August/005082.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg2'
  package(s) announced via the USN-4109-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenJPEG incorrectly handled certain PGX files. An
attacker could possibly use this issue to cause a denial of service or possibly
remote code execution. (CVE-2017-17480)

It was discovered that OpenJPEG incorrectly handled certain files. An attacker
could possibly use this issue to cause a denial of service. (CVE-2018-14423)

It was discovered that OpenJPEG incorrectly handled certain PNM files. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2018-18088)

It was discovered that OpenJPEG incorrectly handled certain BMP files. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2018-5785, CVE-2018-6616)" );
	script_tag( name: "affected", value: "'openjpeg2' package(s) on Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-7", ver: "2.3.0-2build0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libopenjp3d7", ver: "2.3.0-2build0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libopenjpip7", ver: "2.3.0-2build0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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

