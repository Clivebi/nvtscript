if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844094" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2019-11719", "CVE-2019-11727", "CVE-2019-11729" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 18:15:00 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-07-17 02:00:28 +0000 (Wed, 17 Jul 2019)" );
	script_name( "Ubuntu Update for nss USN-4060-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4060-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-July/005012.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nss'
  package(s) announced via the USN-4060-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Henry Corrigan-Gibbs discovered that NSS incorrectly handled importing
certain curve25519 private keys. An attacker could use this issue to cause
NSS to crash, resulting in a denial of service, or possibly obtain
sensitive information. (CVE-2019-11719)

Hubert Kario discovered that NSS incorrectly handled PKCS#1 v1.5 signatures
when using TLSv1.3. An attacker could possibly use this issue to trick NSS
into using PKCS#1 v1.5 signatures, contrary to expectations. This issue
only applied to Ubuntu 19.04. (CVE-2019-11727)

Jonas Allmann discovered that NSS incorrectly handled certain p256-ECDH
public keys. An attacker could possibly use this issue to cause NSS to
crash, resulting in a denial of service. (CVE-2019-11729)" );
	script_tag( name: "affected", value: "'nss' package(s) on Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libnss3", ver: "2:3.35-2ubuntu2.3", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libnss3", ver: "2:3.42-1ubuntu2.1", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libnss3", ver: "2:3.28.4-0ubuntu0.16.04.6", rls: "UBUNTU16.04 LTS" ) )){
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

