if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843006" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-05 05:42:57 +0100 (Thu, 05 Jan 2017)" );
	script_cve_id( "CVE-2016-5285", "CVE-2016-8635", "CVE-2016-9074" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-09 20:15:00 +0000 (Thu, 09 Jan 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for nss USN-3163-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nss'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that NSS incorrectly
  handled certain invalid Diffie-Hellman keys. A remote attacker could possibly
  use this flaw to cause NSS to crash, resulting in a denial of service. This issue
  only applied to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
  (CVE-2016-5285)

Hubert Kario discovered that NSS incorrectly handled Diffie Hellman client
key exchanges. A remote attacker could possibly use this flaw to perform a
small subgroup confinement attack and recover private keys. This issue only
applied to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-8635)

Franziskus Kiefer discovered that NSS incorrectly mitigated certain timing
side-channel attacks. A remote attacker could possibly use this flaw to
recover private keys. (CVE-2016-9074)

This update refreshes the NSS package to version 3.26.2 which includes
the latest CA certificate bundle." );
	script_tag( name: "affected", value: "nss on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3163-1" );
	script_xref( name: "URL", value: "https://www.ubuntu.com/usn/usn-3163-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.10|12\\.04 LTS|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libnss3:i386", ver: "2:3.26.2-0ubuntu0.14.04.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libnss3:amd64", ver: "2:3.26.2-0ubuntu0.14.04.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "libnss3:i386", ver: "2:3.26.2-0ubuntu0.16.10.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libnss3:amd64", ver: "2:3.26.2-0ubuntu0.16.10.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libnss3:i386", ver: "2:3.26.2-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libnss3:amd64", ver: "2:3.26.2-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libnss3:i386", ver: "2:3.26.2-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libnss3:amd64", ver: "2:3.26.2-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

