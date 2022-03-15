if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843087" );
	script_version( "2021-09-16T09:01:51+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 09:01:51 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-10 05:53:47 +0100 (Fri, 10 Mar 2017)" );
	script_cve_id( "CVE-2016-5418", "CVE-2016-6250", "CVE-2016-7166", "CVE-2016-8687", "CVE-2016-8688", "CVE-2016-8689", "CVE-2017-5601" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libarchive USN-3225-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libarchive'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libarchive
  incorrectly handled hardlink entries when extracting archives. A remote attacker
  could possibly use this issue to overwrite arbitrary files. (CVE-2016-5418)
  Christian Wressnegger, Alwin Maier, and Fabian Yamaguchi discovered that
  libarchive incorrectly handled filename lengths when writing ISO9660 archives. A
  remote attacker could use this issue to cause libarchive to crash, resulting in
  a denial of service, or possibly execute arbitrary code. This issue only applied
  to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-6250)
  Alexander Cherepanov discovered that libarchive incorrectly handled recursive
  decompressions. A remote attacker could possibly use this issue to cause
  libarchive to hang, resulting in a denial of service. This issue only applied to
  Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-7166) It was
  discovered that libarchive incorrectly handled non-printable multibyte
  characters in filenames. A remote attacker could possibly use this issue to
  cause libarchive to crash, resulting in a denial of service. (CVE-2016-8687) It
  was discovered that libarchive incorrectly handled line sizes when extracting
  certain archives. A remote attacker could possibly use this issue to cause
  libarchive to crash, resulting in a denial of service. (CVE-2016-8688) It was
  discovered that libarchive incorrectly handled multiple EmptyStream attributes
  when extracting certain 7zip archives. A remote attacker could possibly use this
  issue to cause libarchive to crash, resulting in a denial of service.
  (CVE-2016-8689) Jakub Jirasek discovered that libarchive incorrectly handled
  memory when extracting certain archives. A remote attacker could possibly use
  this issue to cause libarchive to crash, resulting in a denial of service.
  (CVE-2017-5601)" );
	script_tag( name: "affected", value: "libarchive on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3225-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3225-1/" );
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
	if(( res = isdpkgvuln( pkg: "libarchive13:i386", ver: "3.1.2-7ubuntu2.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libarchive13:amd64", ver: "3.1.2-7ubuntu2.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "libarchive13:i386", ver: "3.2.1-2ubuntu0.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libarchive13:amd64", ver: "3.2.1-2ubuntu0.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libarchive12:i386", ver: "3.0.3-6ubuntu1.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libarchive12:amd64", ver: "3.0.3-6ubuntu1.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libarchive13:amd64", ver: "3.1.2-11ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libarchive13:i386", ver: "3.1.2-11ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

