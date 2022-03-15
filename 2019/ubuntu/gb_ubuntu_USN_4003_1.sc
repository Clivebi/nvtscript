if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844032" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2018-15518", "CVE-2018-19870", "CVE-2018-19873" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 09:15:00 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-06-04 02:00:40 +0000 (Tue, 04 Jun 2019)" );
	script_name( "Ubuntu Update for qtbase-opensource-src USN-4003-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU18\\.10|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4003-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-June/004933.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qtbase-opensource-src'
  package(s) announced via the USN-4003-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Qt incorrectly handled certain XML documents. A
remote attacker could use this issue with a specially crafted XML document
to cause Qt to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2018-15518)

It was discovered that Qt incorrectly handled certain GIF images. A remote
attacker could use this issue with a specially crafted GIF image to cause
Qt to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2018-19870)

It was discovered that Qt incorrectly handled certain BMP images. A remote
attacker could use this issue with a specially crafted BMP image to cause
Qt to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2018-19873)" );
	script_tag( name: "affected", value: "'qtbase-opensource-src' package(s) on Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libqt5core5a", ver: "5.9.5+dfsg-0ubuntu2.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libqt5gui5", ver: "5.9.5+dfsg-0ubuntu2.1", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU18.10"){
	if(!isnull( res = isdpkgvuln( pkg: "libqt5core5a", ver: "5.11.1+dfsg-7ubuntu3.1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libqt5gui5", ver: "5.11.1+dfsg-7ubuntu3.1", rls: "UBUNTU18.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libqt5core5a", ver: "5.5.1+dfsg-16ubuntu7.6", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libqt5gui5", ver: "5.5.1+dfsg-16ubuntu7.6", rls: "UBUNTU16.04 LTS" ) )){
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
