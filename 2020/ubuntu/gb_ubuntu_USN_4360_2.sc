if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844432" );
	script_version( "2020-05-20T02:28:18+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-20 02:28:18 +0000 (Wed, 20 May 2020)" );
	script_tag( name: "creation_date", value: "2020-05-16 03:00:15 +0000 (Sat, 16 May 2020)" );
	script_name( "Ubuntu: Security Advisory for json-c (USN-4360-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "USN", value: "4360-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-May/005433.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'json-c'
  package(s) announced via the USN-4360-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4360-1 fixed a vulnerability in json-c. The security fix introduced
a memory leak in some scenarios. This update reverts the security fix
pending further investigation.

We apologize for the inconvenience.

Original advisory details:

It was discovered that json-c incorrectly handled certain JSON files.
An attacker could possibly use this issue to execute arbitrary code." );
	script_tag( name: "affected", value: "'json-c' package(s) on Ubuntu 20.04 LTS, Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libjson-c4", ver: "0.13.1+dfsg-4ubuntu0.2", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libjson-c3", ver: "0.12.1-1.3ubuntu0.2", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libjson-c2", ver: "0.11-4ubuntu2.5", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libjson-c4", ver: "0.13.1+dfsg-7ubuntu0.2", rls: "UBUNTU20.04 LTS" ) )){
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

