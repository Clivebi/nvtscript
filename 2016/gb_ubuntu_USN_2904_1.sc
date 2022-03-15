if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842682" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-10 06:17:04 +0100 (Thu, 10 Mar 2016)" );
	script_cve_id( "CVE-2015-7575", "CVE-2016-1523", "CVE-2016-1930", "CVE-2016-1935" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for thunderbird USN-2904-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Karthikeyan Bhargavan and Gaetan Leurent
  discovered that NSS incorrectly allowed MD5 to be used for TLS 1.2 connections.
  If a remote attacker were able to perform a man-in-the-middle attack, this
  flaw could be exploited to view sensitive information. (CVE-2015-7575)

  Yves Younan discovered that graphite2 incorrectly handled certain malformed
  fonts. If a user were tricked into opening a specially crafted website in a
  browsing context, an attacker could potentially exploit this to cause a
  denial of service via application crash, or execute arbitrary code with the
  privileges of the user invoking Thunderbird. (CVE-2016-1523)

  Bob Clary, Christian Holler, Nils Ohlmeier, Gary Kwong, Jesse Ruderman,
  Carsten Book, and Randell Jesup discovered multiple memory safety issues
  in Thunderbird. If a user were tricked in to opening a specially crafted
  website in a browsing context, an attacker could potentially exploit these
  to cause a denial of service via application crash, or execute arbitrary
  code with the privileges of the user invoking Thunderbird. (CVE-2016-1930)

  Aki Helin discovered a buffer overflow when rendering WebGL content in
  some circumstances. If a user were tricked in to opening a specially
  crafted website in a browsing context, an attacker could potentially
  exploit this to cause a denial of service via application crash, or
  execute arbitrary code with the privileges of the user invoking
  Thunderbird. (CVE-2016-1935)" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2904-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2904-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.6.0+build1-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.6.0+build1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.6.0+build1-0ubuntu0.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

