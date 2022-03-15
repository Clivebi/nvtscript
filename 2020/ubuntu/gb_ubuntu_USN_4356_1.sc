if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844426" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2019-12519", "CVE-2019-12521", "CVE-2019-18860", "CVE-2020-11945" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-11 14:43:00 +0000 (Thu, 11 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-05-14 03:00:26 +0000 (Thu, 14 May 2020)" );
	script_name( "Ubuntu: Security Advisory for squid (USN-4356-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "USN", value: "4356-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-May/005428.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid'
  package(s) announced via the USN-4356-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jeriko One discovered that Squid incorrectly handled certain Edge Side
Includes (ESI) responses. A malicious remote server could cause Squid to
crash, possibly poison the cache, or possibly execute arbitrary code.
(CVE-2019-12519, CVE-2019-12521)

It was discovered that Squid incorrectly handled the hostname parameter to
cachemgr.cgi when certain browsers are used. A remote attacker could
possibly use this issue to inject HTML or invalid characters in the
hostname parameter. This issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04
LTS, and Ubuntu 19.10. (CVE-2019-18860)

Clément Berthaux and Florian Guilbert discovered that Squid incorrectly
handled Digest Authentication nonce values. A remote attacker could
use this issue to replay nonce values, or possibly execute arbitrary code.
(CVE-2020-11945)" );
	script_tag( name: "affected", value: "'squid' package(s) on Ubuntu 20.04 LTS, Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "squid", ver: "4.8-1ubuntu2.3", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "squid", ver: "3.5.27-1ubuntu1.6", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "squid", ver: "3.5.12-1ubuntu7.11", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "squid", ver: "4.10-1ubuntu1.1", rls: "UBUNTU20.04 LTS" ) )){
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

