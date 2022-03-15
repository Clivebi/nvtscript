if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844531" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_cve_id( "CVE-2020-14556", "CVE-2020-14577", "CVE-2020-14578", "CVE-2020-14579", "CVE-2020-14581", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-10 16:15:00 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-08-06 03:00:19 +0000 (Thu, 06 Aug 2020)" );
	script_name( "Ubuntu: Security Advisory for openjdk-8 (USN-4453-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "USN", value: "4453-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-August/005551.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the USN-4453-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Johannes Kuhn discovered that OpenJDK 8 incorrectly handled access control
contexts. An attacker could possibly use this issue to execute arbitrary
code. (CVE-2020-14556)

Philippe Arteau discovered that OpenJDK 8 incorrectly verified names in
TLS server's X.509 certificates. An attacker could possibly use this
issue to obtain sensitive information. (CVE-2020-14577)

It was discovered that OpenJDK 8 incorrectly handled exceptions in
DerInputStream class and in the DerValue.equals() method. An attacker
could possibly use this issue to cause a denial of service.
(CVE-2020-14578, CVE-2020-14579)

It was discovered that OpenJDK 8 incorrectly handled image files. An
attacker could possibly use this issue to obtain sensitive information.
(CVE-2020-14581)

Markus Loewe discovered that OpenJDK 8 incorrectly handled concurrent
access in java.nio.Buffer class. An attacker could use this issue to
bypass sandbox restrictions.
(CVE-2020-14583)

It was discovered that OpenJDK 8 incorrectly handled transformation of
images. An attacker could possibly use this issue to bypass sandbox
restrictions and insert, edit or obtain sensitive information.
(CVE-2020-14593)

Roman Shemyakin discovered that OpenJDK 8 incorrectly handled XML files.
An attacker could possibly use this issue to insert, edit or obtain
sensitive information. (CVE-2020-14621)" );
	script_tag( name: "affected", value: "'openjdk-8' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u265-b01-0ubuntu2~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u265-b01-0ubuntu2~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u265-b01-0ubuntu2~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u265-b01-0ubuntu2~18.04", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u265-b01-0ubuntu2~16.04", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u265-b01-0ubuntu2~16.04", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u265-b01-0ubuntu2~16.04", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-jamvm", ver: "8u265-b01-0ubuntu2~16.04", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u265-b01-0ubuntu2~16.04", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u265-b01-0ubuntu2~20.04", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u265-b01-0ubuntu2~20.04", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u265-b01-0ubuntu2~20.04", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u265-b01-0ubuntu2~20.04", rls: "UBUNTU20.04 LTS" ) )){
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

