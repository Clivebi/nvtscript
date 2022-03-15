if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844340" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2015-9253", "CVE-2020-7059", "CVE-2020-7060" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-19 00:15:00 +0000 (Wed, 19 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-02-18 04:00:28 +0000 (Tue, 18 Feb 2020)" );
	script_name( "Ubuntu: Security Advisory for php7.3 (USN-4279-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4279-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-February/005328.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php7.3'
  package(s) announced via the USN-4279-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that PHP incorrectly handled certain scripts.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM and Ubuntu 16.04 LTS.
(CVE-2015-9253)

It was discovered that PHP incorrectly handled certain inputs. An attacker
could possibly use this issue to expose sensitive information.
(CVE-2020-7059)

It was discovered that PHP incorrectly handled certain inputs.
An attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS
and Ubuntu 19.10. (CVE-2020-7060)" );
	script_tag( name: "affected", value: "'php7.3' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.3", ver: "7.3.11-0ubuntu0.19.10.3", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.3-cgi", ver: "7.3.11-0ubuntu0.19.10.3", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.3-cli", ver: "7.3.11-0ubuntu0.19.10.3", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.3-fpm", ver: "7.3.11-0ubuntu0.19.10.3", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.2", ver: "7.2.24-0ubuntu0.18.04.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-cgi", ver: "7.2.24-0ubuntu0.18.04.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-cli", ver: "7.2.24-0ubuntu0.18.04.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-fpm", ver: "7.2.24-0ubuntu0.18.04.3", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.0", ver: "7.0.33-0ubuntu0.16.04.11", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-cgi", ver: "7.0.33-0ubuntu0.16.04.11", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-cli", ver: "7.0.33-0ubuntu0.16.04.11", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.0-fpm", ver: "7.0.33-0ubuntu0.16.04.11", rls: "UBUNTU16.04 LTS" ) )){
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

