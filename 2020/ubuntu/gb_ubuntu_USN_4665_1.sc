if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844752" );
	script_version( "2021-07-09T02:00:48+0000" );
	script_cve_id( "CVE-2020-8231", "CVE-2020-8284", "CVE-2020-8285", "CVE-2020-8286" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-09 02:00:48 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-12-10 04:00:30 +0000 (Thu, 10 Dec 2020)" );
	script_name( "Ubuntu: Security Advisory for curl (USN-4665-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "USN", value: "4665-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-December/005799.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the USN-4665-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Marc Aldorasi discovered that curl incorrectly handled the libcurl
CURLOPT_CONNECT_ONLY option. This could result in data being sent to the
wrong destination, possibly exposing sensitive information. This issue only
affected Ubuntu 20.10. (CVE-2020-8231)

Varnavas Papaioannou discovered that curl incorrectly handled FTP PASV
responses. An attacker could possibly use this issue to trick curl into
connecting to an arbitrary IP address and be used to perform port scanner
and other information gathering. (CVE-2020-8284)

It was discovered that curl incorrectly handled FTP wildcard matchins. A
remote attacker could possibly use this issue to cause curl to consume
resources and crash, resulting in a denial of service. (CVE-2020-8285)

It was discovered that curl incorrectly handled OCSP response verification.
A remote attacker could possibly use this issue to provide a fraudulent
OCSP response. (CVE-2020-8286)" );
	script_tag( name: "affected", value: "'curl' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.68.0-1ubuntu2.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.68.0-1ubuntu2.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.68.0-1ubuntu2.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl4", ver: "7.68.0-1ubuntu2.4", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.58.0-2ubuntu3.12", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.58.0-2ubuntu3.12", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.58.0-2ubuntu3.12", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl4", ver: "7.58.0-2ubuntu3.12", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.47.0-1ubuntu2.18", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3", ver: "7.47.0-1ubuntu2.18", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.47.0-1ubuntu2.18", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.47.0-1ubuntu2.18", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.68.0-1ubuntu4.2", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.68.0-1ubuntu4.2", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.68.0-1ubuntu4.2", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl4", ver: "7.68.0-1ubuntu4.2", rls: "UBUNTU20.10" ) )){
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

