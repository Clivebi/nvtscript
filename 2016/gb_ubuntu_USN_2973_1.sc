if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842769" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-19 05:21:10 +0200 (Thu, 19 May 2016)" );
	script_cve_id( "CVE-2016-2805", "CVE-2016-2807", "CVE-2016-1938", "CVE-2016-1978", "CVE-2016-1979" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for thunderbird USN-2973-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Christian Holler, Tyson Smith, and Phil
  Ringalda discovered multiple memory safety issues in Thunderbird. If a user
  were tricked in to opening a specially crafted message, an attacker could
  potentially exploit these to cause a denial of service via application crash,
  or execute arbitrary code. (CVE-2016-2805, CVE-2016-2807)

  Hanno B&#246 ck discovered that calculations with mp_div and mp_exptmod in NSS
  produce incorrect results in some circumstances, resulting in
  cryptographic weaknesses. (CVE-2016-1938)

  A use-after-free was discovered in ssl3_HandleECDHServerKeyExchange in
  NSS. A remote attacker could potentially exploit this to cause a denial of
  service via application crash, or execute arbitrary code. (CVE-2016-1978)

  A use-after-free was discovered in PK11_ImportDERPrivateKeyInfoAndReturnKey
  in NSS. A remote attacker could potentially exploit this to cause a denial
  of service via application crash, or execute arbitrary code.
  (CVE-2016-1979)" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 16.04 LTS,
  Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2973-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2973-1/" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.8.0+build1-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.8.0+build1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.8.0+build1-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.8.0+build1-0ubuntu0.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

