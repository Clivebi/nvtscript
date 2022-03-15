if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843913" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2018-5744", "CVE-2018-5745", "CVE-2019-6465" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-05 16:58:00 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-02-23 04:07:11 +0100 (Sat, 23 Feb 2019)" );
	script_name( "Ubuntu Update for bind9 USN-3893-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|18\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3893-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3893-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind9'
  package(s) announced via the USN-3893-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Toshifumi Sakaguchi discovered that Bind incorrectly handled memory. A
remote attacker could possibly use this issue to cause Bind to consume
resources, leading to a denial of service. This issue only affected Ubuntu
18.04 LTS and Ubuntu 18.10. (CVE-2018-5744)

It was discovered that Bind incorrectly handled certain trust anchors when
used with the 'managed-keys' feature. A remote attacker could possibly use
this issue to cause Bind to crash, resulting in a denial of service.
(CVE-2018-5745)

It was discovered that Bind incorrectly handled certain controls for zone
transfers, contrary to expectations. (CVE-2019-6465)" );
	script_tag( name: "affected", value: "bind9 on Ubuntu 18.10,
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
	if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.9.5.dfsg-3ubuntu0.19", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.11.3+dfsg-1ubuntu1.5", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.11.4+dfsg-3ubuntu5.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.10.3.dfsg.P4-8ubuntu1.12", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

