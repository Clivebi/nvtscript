if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844486" );
	script_version( "2021-07-09T02:00:48+0000" );
	script_cve_id( "CVE-2020-10730", "CVE-2020-10745", "CVE-2020-10760" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-09 02:00:48 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-23 05:15:00 +0000 (Mon, 23 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-07-03 03:01:47 +0000 (Fri, 03 Jul 2020)" );
	script_name( "Ubuntu: Security Advisory for samba (USN-4409-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "USN", value: "4409-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-July/005497.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the USN-4409-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Andrew Bartlett discovered that Samba incorrectly handled certain LDAP queries.
A remote attacker could use this issue to cause Samba to crash, resulting
in a denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 18.04 LTS, Ubuntu 19.10 and Ubuntu 20.04 LTS. (CVE-2020-10730)

Douglas Bagnall discovered that Samba incorrectly handled certain queries.
A remote attacker could possibly use this issue to cause a denial of service.
(CVE-2020-10745)

Andrei Popa discovered that Samba incorrectly handled certain LDAP queries.
A remote attacker could use this issue to cause Samba to crash, resulting
in a denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 18.04 LTS, Ubuntu 19.10 and Ubuntu 20.04 LTS.
(CVE-2020-10760)" );
	script_tag( name: "affected", value: "'samba' package(s) on Ubuntu 20.04 LTS, Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.10.7+dfsg-0ubuntu2.6", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.7.6+dfsg~ubuntu-0ubuntu2.17", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.3.11+dfsg-0ubuntu0.16.04.28", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.11.6+dfsg-0ubuntu1.3", rls: "UBUNTU20.04 LTS" ) )){
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

