if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844295" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2019-11045", "CVE-2019-11046", "CVE-2019-11047", "CVE-2019-11050" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-17 04:15:00 +0000 (Sun, 17 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-01-16 04:00:13 +0000 (Thu, 16 Jan 2020)" );
	script_name( "Ubuntu Update for php7.3 USN-4239-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.10|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4239-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-January/005272.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php7.3'
  package(s) announced via the USN-4239-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that PHP incorrectly handled certain files. An attacker
could possibly use this issue to cause a denial of service. This issue only affected
Ubuntu 14.04 ESM, 16.04 LTS, 18.04 LTS, 19.04 and 19.10. (CVE-2019-11045)

It was discovered that PHP incorrectly handled certain inputs. An attacker
could possibly use this issue to expose sensitive information.
(CVE-2019-11046)

It was discovered that PHP incorrectly handled certain images. An attacker
could possibly use this issue to access sensitive information.
(CVE-2019-11047, CVE-2019-11050)" );
	script_tag( name: "affected", value: "'php7.3' package(s) on Ubuntu 19.10, Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.2", ver: "7.2.24-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-bcmath", ver: "7.2.24-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-cgi", ver: "7.2.24-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-cli", ver: "7.2.24-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-fpm", ver: "7.2.24-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-mbstring", ver: "7.2.24-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-xmlrpc", ver: "7.2.24-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.3", ver: "7.3.11-0ubuntu0.19.10.2", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.3-bcmath", ver: "7.3.11-0ubuntu0.19.10.2", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.3-cgi", ver: "7.3.11-0ubuntu0.19.10.2", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.3-cli", ver: "7.3.11-0ubuntu0.19.10.2", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.3-fpm", ver: "7.3.11-0ubuntu0.19.10.2", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.3-mbstring", ver: "7.3.11-0ubuntu0.19.10.2", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.3-xmlrpc", ver: "7.3.11-0ubuntu0.19.10.2", rls: "UBUNTU19.10" ) )){
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
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.2", ver: "7.2.24-0ubuntu0.19.04.2", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-bcmath", ver: "7.2.24-0ubuntu0.19.04.2", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-cgi", ver: "7.2.24-0ubuntu0.19.04.2", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-cli", ver: "7.2.24-0ubuntu0.19.04.2", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-fpm", ver: "7.2.24-0ubuntu0.19.04.2", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-mbstring", ver: "7.2.24-0ubuntu0.19.04.2", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-xmlrpc", ver: "7.2.24-0ubuntu0.19.04.2", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.0", ver: "7.0.33-0ubuntu0.16.04.9", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-bcmath", ver: "7.0.33-0ubuntu0.16.04.9", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-cgi", ver: "7.0.33-0ubuntu0.16.04.9", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-cli", ver: "7.0.33-0ubuntu0.16.04.9", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-fpm", ver: "7.0.33-0ubuntu0.16.04.9", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-mbstring", ver: "7.0.33-0ubuntu0.16.04.9", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-xmlrpc", ver: "7.0.33-0ubuntu0.16.04.9", rls: "UBUNTU16.04 LTS" ) )){
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

