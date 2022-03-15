if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843848" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_cve_id( "CVE-2018-0734", "CVE-2018-0735", "CVE-2018-5407" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-12-07 07:39:41 +0100 (Fri, 07 Dec 2018)" );
	script_name( "Ubuntu Update for openssl USN-3840-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|18\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3840-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3840-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the USN-3840-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Samuel Weiser discovered that OpenSSL incorrectly handled DSA signing. An
attacker could possibly use this issue to perform a timing side-channel
attack and recover private DSA keys. (CVE-2018-0734)

Samuel Weiser discovered that OpenSSL incorrectly handled ECDSA signing. An
attacker could possibly use this issue to perform a timing side-channel
attack and recover private ECDSA keys. This issue only affected Ubuntu
18.04 LTS and Ubuntu 18.10. (CVE-2018-0735)

Billy Bob Brumley, Cesar Pereida Garcia, Sohaib ul Hassan, Nicola Tuveri,
and Alejandro Cabrera Aldaya discovered that Simultaneous Multithreading
(SMT) architectures are vulnerable to side-channel leakage. This issue is
known as 'PortSmash'. An attacker could possibly use this issue to perform
a timing side-channel attack and recover private keys. (CVE-2018-5407)" );
	script_tag( name: "affected", value: "openssl on Ubuntu 18.10,
  Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
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
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1f-1ubuntu2.27", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.2n-1ubuntu5.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.1", ver: "1.1.0g-2ubuntu4.3", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.2n-1ubuntu6.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.1", ver: "1.1.1-1ubuntu2.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.2g-1ubuntu4.14", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

