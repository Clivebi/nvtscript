if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844918" );
	script_version( "2021-08-17T14:01:00+0000" );
	script_cve_id( "CVE-2021-2163" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 13:53:00 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-30 03:00:55 +0000 (Fri, 30 Apr 2021)" );
	script_name( "Ubuntu: Security Advisory for openjdk-8 (USN-4892-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4892-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-April/005991.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the USN-4892-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenJDK incorrectly verified Jar signatures. An
attacker could possibly use this issue to bypass intended security
restrictions when using Jar files signed with a disabled algorithm." );
	script_tag( name: "affected", value: "'openjdk-8' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk", ver: "11.0.11+9-0ubuntu2~20.04", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre", ver: "11.0.11+9-0ubuntu2~20.04", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-headless", ver: "11.0.11+9-0ubuntu2~20.04", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-zero", ver: "11.0.11+9-0ubuntu2~20.04", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u292-b10-0ubuntu1~20.04", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u292-b10-0ubuntu1~20.04", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u292-b10-0ubuntu1~20.04", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u292-b10-0ubuntu1~20.04", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk", ver: "11.0.11+9-0ubuntu2~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre", ver: "11.0.11+9-0ubuntu2~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-headless", ver: "11.0.11+9-0ubuntu2~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-zero", ver: "11.0.11+9-0ubuntu2~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u292-b10-0ubuntu1~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u292-b10-0ubuntu1~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u292-b10-0ubuntu1~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u292-b10-0ubuntu1~18.04", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u292-b10-0ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u292-b10-0ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u292-b10-0ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u292-b10-0ubuntu1~16.04.1", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk", ver: "11.0.11+9-0ubuntu2~20.10", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre", ver: "11.0.11+9-0ubuntu2~20.10", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-headless", ver: "11.0.11+9-0ubuntu2~20.10", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-zero", ver: "11.0.11+9-0ubuntu2~20.10", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u292-b10-0ubuntu1~20.10", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u292-b10-0ubuntu1~20.10", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u292-b10-0ubuntu1~20.10", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u292-b10-0ubuntu1~20.10", rls: "UBUNTU20.10" ) )){
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

