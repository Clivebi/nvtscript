if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843171" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-17 06:53:28 +0200 (Wed, 17 May 2017)" );
	script_cve_id( "CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5436", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5467", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5437", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5442", "CVE-2017-5449", "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5460", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5469", "CVE-2017-5459", "CVE-2017-5441", "CVE-2017-5435", "CVE-2017-10195", "CVE-2017-10196", "CVE-2017-10197", "CVE-2017-5462", "CVE-2017-5461" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-07 17:53:00 +0000 (Tue, 07 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for thunderbird USN-3278-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in
  Thunderbird. If a user were tricked in to opening a specially crafted message,
  an attacker could potentially exploit these to read uninitialized memory, cause
  a denial of service via application crash, or execute arbitrary code.
  (CVE-2017-5429, CVE-2017-5430, CVE-2017-5436, CVE-2017-5443, CVE-2017-5444,
  CVE-2017-5445, CVE-2017-5446, CVE-2017-5447, CVE-2017-5461, CVE-2017-5467)
  Multiple security issues were discovered in Thunderbird. If a user were tricked
  in to opening a specially crafted website in a browsing context, an attacker
  could potentially exploit these to spoof the addressbar contents, conduct
  cross-site scripting (XSS) attacks, cause a denial of service via application
  crash, or execute arbitrary code. (CVE-2017-5432, CVE-2017-5433, CVE-2017-5434,
  CVE-2017-5435, CVE-2017-5437, CVE-2017-5438, CVE-2017-5439, CVE-2017-5440,
  CVE-2017-5441, CVE-2017-5442, CVE-2017-5449, CVE-2017-5451, CVE-2017-5454,
  CVE-2017-5459, CVE-2017-5460, CVE-2017-5464, CVE-2017-5465, CVE-2017-5466,
  CVE-2017-5469, CVE-2017-10195, CVE-2017-10196, CVE-2017-10197) A flaw was
  discovered in the DRBG number generation in NSS. If an attacker were able to
  perform a man-in-the-middle attack, this flaw could potentially be exploited to
  view sensitive information. (CVE-2017-5462)" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3278-1" );
	script_xref( name: "URL", value: "https://www.ubuntu.com/usn/usn-3278-1" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:52.1.1+build1-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:52.1.1+build1-0ubuntu0.17.04.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:52.1.1+build1-0ubuntu0.16.10.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:52.1.1+build1-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

