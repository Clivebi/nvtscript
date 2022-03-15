if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.845027" );
	script_version( "2021-08-24T12:01:48+0000" );
	script_cve_id( "CVE-2021-32815", "CVE-2021-34334", "CVE-2021-37620", "CVE-2021-37622", "CVE-2021-34335", "CVE-2021-37615", "CVE-2021-37616", "CVE-2021-37618", "CVE-2021-37619", "CVE-2021-37621", "CVE-2021-37623" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 12:01:48 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-20 15:02:00 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-18 03:00:28 +0000 (Wed, 18 Aug 2021)" );
	script_name( "Ubuntu: Security Advisory for exiv2 (USN-5043-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "Advisory-ID", value: "USN-5043-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-August/006146.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exiv2'
  package(s) announced via the USN-5043-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Exiv2 incorrectly handled certain image files.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2021-32815, CVE-2021-34334, CVE-2021-37620, CVE-2021-37622)

It was discovered that Exiv2 incorrectly handled certain image files.
An attacker could possibly use this issue to cause a denial of service.
These issues only affected Ubuntu 20.04 LTS and Ubuntu 21.04.
(CVE-2021-34335, CVE-2021-37615, CVE-2021-37616, CVE-2021-37618,
CVE-2021-37619, CVE-2021-37621, CVE-2021-37623)" );
	script_tag( name: "affected", value: "'exiv2' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libexiv2-14", ver: "0.25-3.1ubuntu0.18.04.11", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libexiv2-27", ver: "0.27.2-8ubuntu2.6", rls: "UBUNTU20.04 LTS" ) )){
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

