if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843615" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-15 06:19:51 +0200 (Wed, 15 Aug 2018)" );
	script_cve_id( "CVE-2018-10858", "CVE-2018-10918", "CVE-2018-10919", "CVE-2018-1139" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-26 08:15:00 +0000 (Wed, 26 Jun 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for samba USN-3738-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Svyatoslav Phirsov discovered that the Samba
  libsmbclient library incorrectly handled extra long filenames. A malicious server
  could use this issue to cause Samba to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2018-10858)

Volker Mauel discovered that Samba incorrectly handled database output.
When used as an Active Directory Domain Controller, a remote authenticated
attacker could use this issue to cause Samba to crash, resulting in a
denial of service. This issue only affected Ubuntu 18.04 LTS.
(CVE-2018-10918)

Phillip Kuhrt discovered that the Samba LDAP server incorrectly handled
certain confidential attribute values. A remote authenticated attacker
could possibly use this issue to obtain certain sensitive information.
(CVE-2018-10919)

Vivek Das discovered that Samba incorrectly handled NTLMv1 being explicitly
disabled on the server. A remote user could possibly be authenticated using
NTLMv1, contrary to expectations. This issue only affected Ubuntu 18.04
LTS. (CVE-2018-1139)" );
	script_tag( name: "affected", value: "samba on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3738-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3738-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.3.11+dfsg-0ubuntu0.14.04.16", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.3.11+dfsg-0ubuntu0.14.04.16", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.7.6+dfsg~ubuntu-0ubuntu2.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.7.6+dfsg~ubuntu-0ubuntu2.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.3.11+dfsg-0ubuntu0.16.04.15", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.3.11+dfsg-0ubuntu0.16.04.15", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

