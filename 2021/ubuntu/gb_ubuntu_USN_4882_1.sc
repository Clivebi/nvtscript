if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844872" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2020-10663", "CVE-2020-10933", "CVE-2020-25613" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-04 07:15:00 +0000 (Sun, 04 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-03-19 04:00:21 +0000 (Fri, 19 Mar 2021)" );
	script_name( "Ubuntu: Security Advisory for ruby2.7 (USN-4882-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4882-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-March/005938.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby2.7'
  package(s) announced via the USN-4882-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Ruby JSON gem incorrectly handled certain JSON
files. If a user or automated system were tricked into parsing a specially
crafted JSON file, a remote attacker could use this issue to execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04
LTS. (CVE-2020-10663)

It was discovered that Ruby incorrectly handled certain socket memory
operations. A remote attacker could possibly use this issue to obtain
sensitive information. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-10933)

It was discovered that Ruby incorrectly handled certain transfer-encoding
headers when using Webrick. A remote attacker could possibly use this issue
to bypass a reverse proxy. (CVE-2020-25613)" );
	script_tag( name: "affected", value: "'ruby2.7' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libruby2.7", ver: "2.7.0-5ubuntu1.3", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby2.7", ver: "2.7.0-5ubuntu1.3", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libruby2.5", ver: "2.5.1-1ubuntu1.8", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby2.5", ver: "2.5.1-1ubuntu1.8", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libruby2.3", ver: "2.3.1-2~ubuntu16.04.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby2.3", ver: "2.3.1-2~ubuntu16.04.15", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libruby2.7", ver: "2.7.1-3ubuntu1.2", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby2.7", ver: "2.7.1-3ubuntu1.2", rls: "UBUNTU20.10" ) )){
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

