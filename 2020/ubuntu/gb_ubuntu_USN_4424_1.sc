if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844499" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2020-11933", "CVE-2020-11934" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-05 18:54:00 +0000 (Wed, 05 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-16 03:00:18 +0000 (Thu, 16 Jul 2020)" );
	script_name( "Ubuntu: Security Advisory for snapd (USN-4424-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "USN", value: "4424-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-July/005515.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'snapd'
  package(s) announced via the USN-4424-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that cloud-init as managed by snapd on Ubuntu Core 16
and Ubuntu Core 18 devices ran on every boot without restrictions. A
physical attacker could exploit this to craft cloud-init
user-data/meta-data via external media to perform arbitrary changes on
the device to bypass intended security mechanisms such as full disk
encryption. This issue did not affect traditional Ubuntu systems.
(CVE-2020-11933)

It was discovered that snapctl user-open allowed altering the
XDG_DATA_DIRS environment variable when calling the system xdg-open. A
malicious snap could exploit this to bypass intended access restrictions
to control how the host system xdg-open script opens the URL. This issue
did not affect Ubuntu Core systems. (CVE-2020-11934)" );
	script_tag( name: "affected", value: "'snapd' package(s) on Ubuntu 20.04 LTS, Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "snapd", ver: "2.45.1+19.10.2", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "snapd", ver: "2.45.1+18.04.2", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "snapd", ver: "2.45.1ubuntu0.2", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "snapd", ver: "2.45.1+20.04.2", rls: "UBUNTU20.04 LTS" ) )){
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

