if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843363" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-15 07:29:47 +0100 (Wed, 15 Nov 2017)" );
	script_cve_id( "CVE-2017-15098", "CVE-2017-15099" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-28 10:29:00 +0000 (Tue, 28 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for postgresql-9.6 USN-3479-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql-9.6'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "David Rowley discovered that PostgreSQL
incorrectly handled memory when processing certain JSON functions. A remote
attacker could possibly use this issue to obtain sensitive information.
(CVE-2017-15098)

Dean Rasheed discovered that PostgreSQL incorrectly enforced SELECT
privileges when processing INSERT ... ON CONFLICT DO UPDATE commands. A
remote attacker could possibly use this issue to obtain sensitive
information. This issue only affected Ubuntu 16.04 LTS, Ubuntu 17.04 and
Ubuntu 17.10." );
	script_tag( name: "affected", value: "postgresql-9.6 on Ubuntu 17.10,
  Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3479-1" );
	script_xref( name: "URL", value: "https://usn.ubuntu.com/usn/usn-3479-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|17\\.04|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "postgresql-9.3", ver: "9.3.20-0ubuntu0.14.04", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "postgresql-9.6", ver: "9.6.6-0ubuntu0.17.10", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "postgresql-9.6", ver: "9.6.6-0ubuntu0.17.04", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "postgresql-9.5", ver: "9.5.10-0ubuntu0.16.04", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

