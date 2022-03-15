if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844953" );
	script_version( "2021-08-20T06:00:57+0000" );
	script_cve_id( "CVE-2021-29463", "CVE-2021-29464", "CVE-2021-29473", "CVE-2021-32617", "CVE-2021-29623" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 06:00:57 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-10 15:31:00 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-26 03:00:29 +0000 (Wed, 26 May 2021)" );
	script_name( "Ubuntu: Security Advisory for exiv2 (USN-4964-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4964-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-May/006037.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exiv2'
  package(s) announced via the USN-4964-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Exiv2 incorrectly handled certain files.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 20.04 LTS, Ubuntu 20.10 and Ubuntu 21.04.
(CVE-2021-29463)

It was discovered that Exiv2 incorrectly handled certain files.
An attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 20.04 LTS, Ubuntu 20.10 and Ubuntu 21.04.
(CVE-2021-29464)

It was discovered that Exiv2 incorrectly handled certain files.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2021-29473, CVE-2021-32617)

It was discovered that Exiv2 incorrectly handled certain files.
An attacker could possibly use this issue to expose sensitive information.
This issue only affected Ubuntu 20.04 LTS, Ubuntu 20.10 and Ubuntu 21.04.
(CVE-2021-29623)" );
	script_tag( name: "affected", value: "'exiv2' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "exiv2", ver: "0.27.2-8ubuntu2.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libexiv2-27", ver: "0.27.2-8ubuntu2.4", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "exiv2", ver: "0.25-3.1ubuntu0.18.04.9", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libexiv2-14", ver: "0.25-3.1ubuntu0.18.04.9", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "exiv2", ver: "0.27.3-3ubuntu0.4", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libexiv2-27", ver: "0.27.3-3ubuntu0.4", rls: "UBUNTU20.10" ) )){
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

