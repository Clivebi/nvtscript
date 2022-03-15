if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843311" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-19 07:42:23 +0200 (Tue, 19 Sep 2017)" );
	script_cve_id( "CVE-2017-0663", "CVE-2017-7375", "CVE-2017-7376", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-17 15:15:00 +0000 (Fri, 17 May 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libxml2 USN-3424-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that a type confusion
  error existed in libxml2. An attacker could use this to specially construct XML
  data that could cause a denial of service or possibly execute arbitrary code.
  (CVE-2017-0663) It was discovered that libxml2 did not properly validate parsed
  entity references. An attacker could use this to specially construct XML data
  that could expose sensitive information. (CVE-2017-7375) It was discovered that
  a buffer overflow existed in libxml2 when handling HTTP redirects. An attacker
  could use this to specially construct XML data that could cause a denial of
  service or possibly execute arbitrary code. (CVE-2017-7376) Marcel Bhme and
  Van-Thuan Pham discovered a buffer overflow in libxml2 when handling elements.
  An attacker could use this to specially construct XML data that could cause a
  denial of service or possibly execute arbitrary code. (CVE-2017-9047) Marcel
  Bhme and Van-Thuan Pham discovered a buffer overread in libxml2 when handling
  elements. An attacker could use this to specially construct XML data that could
  cause a denial of service. (CVE-2017-9048) Marcel Bhme and Van-Thuan Pham
  discovered multiple buffer overreads in libxml2 when handling parameter-entity
  references. An attacker could use these to specially construct XML data that
  could cause a denial of service. (CVE-2017-9049, CVE-2017-9050)" );
	script_tag( name: "affected", value: "libxml2 on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3424-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3424-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libxml2:amd64", ver: "2.9.1+dfsg1-3ubuntu4.10", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libxml2:i386", ver: "2.9.1+dfsg1-3ubuntu4.10", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "libxml2:amd64", ver: "2.9.4+dfsg1-2.2ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libxml2:i386", ver: "2.9.4+dfsg1-2.2ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libxml2:amd64", ver: "2.9.3+dfsg1-1ubuntu0.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libxml2:i386", ver: "2.9.3+dfsg1-1ubuntu0.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

