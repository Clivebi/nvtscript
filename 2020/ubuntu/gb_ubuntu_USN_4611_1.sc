if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844691" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2020-14318", "CVE-2020-14323", "CVE-2020-14383" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-24 16:15:00 +0000 (Thu, 24 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-03 04:00:37 +0000 (Tue, 03 Nov 2020)" );
	script_name( "Ubuntu: Security Advisory for samba (USN-4611-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "USN", value: "4611-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-November/005734.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the USN-4611-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Steven French discovered that Samba incorrectly handled ChangeNotify
permissions. A remote attacker could possibly use this issue to obtain file
name information. (CVE-2020-14318)

Bas Alberts discovered that Samba incorrectly handled certain winbind
requests. A remote attacker could possibly use this issue to cause winbind
to crash, resulting in a denial of service. (CVE-2020-14323)

Francis Brosnan Blázquez discovered that Samba incorrectly handled certain
invalid DNS records. A remote attacker could possibly use this issue to
cause the DNS server to crash, resulting in a denial of service.
(CVE-2020-14383)" );
	script_tag( name: "affected", value: "'samba' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.11.6+dfsg-0ubuntu1.6", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.7.6+dfsg~ubuntu-0ubuntu2.21", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.3.11+dfsg-0ubuntu0.16.04.32", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "2:4.12.5+dfsg-3ubuntu4.1", rls: "UBUNTU20.10" ) )){
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

