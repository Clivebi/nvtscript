if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844654" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2020-7069", "CVE-2020-7070" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-10-15 03:00:30 +0000 (Thu, 15 Oct 2020)" );
	script_name( "Ubuntu: Security Advisory for php7.4 (USN-4583-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "USN", value: "4583-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-October/005695.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php7.4'
  package(s) announced via the USN-4583-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that PHP incorrectly handled certain encrypt ciphers.
An attacker could possibly use this issue to decrease security or cause
incorrect encryption data. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS.  (CVE-2020-7069)

It was discorevered that PHP incorrectly handled certain HTTP cookies.
An attacker could possibly use this issue to forge cookie which is supposed to
be secure. (CVE-2020-7070)" );
	script_tag( name: "affected", value: "'php7.4' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.2", ver: "7.2.24-0ubuntu0.18.04.7", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-cgi", ver: "7.2.24-0ubuntu0.18.04.7", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-cli", ver: "7.2.24-0ubuntu0.18.04.7", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-curl", ver: "7.2.24-0ubuntu0.18.04.7", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-fpm", ver: "7.2.24-0ubuntu0.18.04.7", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.0", ver: "7.0.33-0ubuntu0.16.04.16", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-cgi", ver: "7.0.33-0ubuntu0.16.04.16", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-cli", ver: "7.0.33-0ubuntu0.16.04.16", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-curl", ver: "7.0.33-0ubuntu0.16.04.16", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-fpm", ver: "7.0.33-0ubuntu0.16.04.16", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.4", ver: "7.4.3-4ubuntu2.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.4-cgi", ver: "7.4.3-4ubuntu2.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.4-cli", ver: "7.4.3-4ubuntu2.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.4-curl", ver: "7.4.3-4ubuntu2.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.4-fpm", ver: "7.4.3-4ubuntu2.4", rls: "UBUNTU20.04 LTS" ) )){
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

