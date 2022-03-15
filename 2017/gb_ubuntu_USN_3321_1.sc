if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843237" );
	script_version( "2021-09-08T14:41:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 14:41:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-14 15:55:17 +0530 (Fri, 14 Jul 2017)" );
	script_cve_id( "CVE-2017-5470", "CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751", "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7756", "CVE-2017-7757", "CVE-2017-7758", "CVE-2017-7764", "CVE-2017-7771", "CVE-2017-7772", "CVE-2017-7773", "CVE-2017-7774", "CVE-2017-7775", "CVE-2017-7776", "CVE-2017-7777", "CVE-2017-7778" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-03 14:16:00 +0000 (Fri, 03 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for thunderbird USN-3321-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in
  Thunderbird. If a user were tricked in to opening a specially crafted website in
  a browsing context, an attacker could potentially exploit these to cause a
  denial of service, read uninitialized memory, obtain sensitive information or
  execute arbitrary code. (CVE-2017-5470, CVE-2017-5472, CVE-2017-7749,
  CVE-2017-7750, CVE-2017-7751, CVE-2017-7752, CVE-2017-7754, CVE-2017-7756,
  CVE-2017-7757, CVE-2017-7758, CVE-2017-7764) Multiple security issues were
  discovered in the Graphite 2 library used by Thunderbird. If a user were tricked
  in to opening a specially crafted message, an attacker could potentially exploit
  these to cause a denial of service, read uninitialized memory, or execute
  arbitrary code. (CVE-2017-7771, CVE-2017-7772, CVE-2017-7773, CVE-2017-7774,
  CVE-2017-7775, CVE-2017-7776, CVE-2017-7777, CVE-2017-7778)" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3321-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3321-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:52.2.1+build1-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:52.2.1+build1-0ubuntu0.17.04.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:52.2.1+build1-0ubuntu0.16.10.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:52.2.1+build1-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

