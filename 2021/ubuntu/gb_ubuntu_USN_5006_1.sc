if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844997" );
	script_version( "2021-08-17T14:01:00+0000" );
	script_cve_id( "CVE-2020-7068", "CVE-2020-7071", "CVE-2021-21702", "CVE-2021-21704", "CVE-2021-21705" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-15 15:15:00 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-08 03:00:24 +0000 (Thu, 08 Jul 2021)" );
	script_name( "Ubuntu: Security Advisory for php7.4 (USN-5006-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-5006-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-July/006097.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php7.4'
  package(s) announced via the USN-5006-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that PHP incorrectly handled certain PHAR files. A remote
attacker could possibly use this issue to cause PHP to crash, resulting in
a denial of service, or possibly obtain sensitive information. This issue
only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-7068)

It was discovered that PHP incorrectly handled parsing URLs with passwords.
A remote attacker could possibly use this issue to cause PHP to mis-parse
the URL and produce wrong data. This issue only affected Ubuntu 18.04 LTS,
Ubuntu 20.04 LTS, and Ubuntu 20.10. (CVE-2020-7071)

It was discovered that PHP incorrectly handled certain malformed XML data
when being parsed by the SOAP extension. A remote attacker could possibly
use this issue to cause PHP to crash, resulting in a denial of service.
This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu
20.10. (CVE-2021-21702)

It was discovered that PHP incorrectly handled the pdo_firebase module. A
remote attacker could possibly use this issue to cause PHP to crash,
resulting in a denial of service. (CVE-2021-21704)

It was discovered that PHP incorrectly handled the FILTER_VALIDATE_URL
check. A remote attacker could possibly use this issue to perform a server-
side request forgery attack. (CVE-2021-21705)" );
	script_tag( name: "affected", value: "'php7.4' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.4", ver: "7.4.3-4ubuntu2.5", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.4-cgi", ver: "7.4.3-4ubuntu2.5", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.4-cli", ver: "7.4.3-4ubuntu2.5", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.4-fpm", ver: "7.4.3-4ubuntu2.5", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.2", ver: "7.2.24-0ubuntu0.18.04.8", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-cgi", ver: "7.2.24-0ubuntu0.18.04.8", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-cli", ver: "7.2.24-0ubuntu0.18.04.8", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.2-fpm", ver: "7.2.24-0ubuntu0.18.04.8", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.4", ver: "7.4.9-1ubuntu1.2", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.4-cgi", ver: "7.4.9-1ubuntu1.2", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.4-cli", ver: "7.4.9-1ubuntu1.2", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "php7.4-fpm", ver: "7.4.9-1ubuntu1.2", rls: "UBUNTU20.10" ) )){
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

