if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844301" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_cve_id( "CVE-2019-14902", "CVE-2019-14907", "CVE-2019-19344" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-29 13:15:00 +0000 (Sat, 29 May 2021)" );
	script_tag( name: "creation_date", value: "2020-01-22 04:00:35 +0000 (Wed, 22 Jan 2020)" );
	script_name( "Ubuntu Update for samba USN-4244-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.10|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4244-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-January/005280.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the USN-4244-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Samba did not automatically replicate ACLs set to
inherit down a subtree on AD Directory, contrary to expectations. This
issue was only addressed in Ubuntu 18.04 LTS, Ubuntu 19.04 and Ubuntu
19.10. (CVE-2019-14902)

Robert wicki discovered that Samba incorrectly handled certain character
conversions when the log level is set to 3 or above. In certain
environments, a remote attacker could possibly use this issue to cause
Samba to crash, resulting in a denial of service. (CVE-2019-14907)

Christian Naumer discovered that Samba incorrectly handled DNS zone
scavenging. This issue could possibly result in some incorrect data being
written to the DB. This issue only applied to Ubuntu 19.04 and Ubuntu
19.10. (CVE-2019-19344)" );
	script_tag( name: "affected", value: "'samba' package(s) on Ubuntu 19.10, Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.7.6+dfsg~ubuntu-0ubuntu2.15", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.10.7+dfsg-0ubuntu2.4", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.10.0+dfsg-0ubuntu2.8", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.3.11+dfsg-0ubuntu0.16.04.25", rls: "UBUNTU16.04 LTS" ) )){
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

