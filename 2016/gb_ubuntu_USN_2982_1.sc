if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842766" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-18 05:19:40 +0200 (Wed, 18 May 2016)" );
	script_cve_id( "CVE-2016-4353", "CVE-2016-4354", "CVE-2016-4355", "CVE-2016-4356", "CVE-2016-4574", "CVE-2016-4579" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-29 13:49:00 +0000 (Fri, 29 Nov 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libksba USN-2982-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libksba'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Hanno B&#246 ck discovered that Libksba
  incorrectly handled decoding certain BER data. An attacker could use this issue
  to cause Libksba to crash, resulting in a denial of service. This issue only
  applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2016-4353)

  Hanno B&#246 ck discovered that Libksba incorrectly handled decoding certain BER
  data. An attacker could use this issue to cause Libksba to crash, resulting
  in a denial of service, or possibly execute arbitrary code. This issue only
  applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2016-4354,
  CVE-2016-4355)

  Hanno B&#246 ck discovered that Libksba incorrectly handled incorrect utf-8
  strings when decoding certain DN data. An attacker could use this issue to
  cause Libksba to crash, resulting in a denial of service, or possibly
  execute arbitrary code. This issue only applied to Ubuntu 12.04 LTS and
  Ubuntu 14.04 LTS. (CVE-2016-4356)

  Pascal Cuoq discovered that Libksba incorrectly handled incorrect utf-8
  strings when decoding certain DN data. An attacker could use this issue to
  cause Libksba to crash, resulting in a denial of service, or possibly
  execute arbitrary code. (CVE-2016-4574)

  Pascal Cuoq discovered that Libksba incorrectly handled decoding certain
  data. An attacker could use this issue to cause Libksba to crash, resulting
  in a denial of service. (CVE-2016-4579)" );
	script_tag( name: "affected", value: "libksba on Ubuntu 16.04 LTS,
  Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2982-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2982-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|16\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libksba8:i386", ver: "1.3.0-3ubuntu0.14.04.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libksba8:amd64", ver: "1.3.0-3ubuntu0.14.04.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libksba8:i386", ver: "1.2.0-2ubuntu0.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libksba8:amd64", ver: "1.2.0-2ubuntu0.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libksba8:i386", ver: "1.3.3-1ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libksba8:amd64", ver: "1.3.3-1ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libksba8:i386", ver: "1.3.3-1ubuntu0.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libksba8:amd64", ver: "1.3.3-1ubuntu0.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

