if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842723" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-06 15:29:31 +0530 (Fri, 06 May 2016)" );
	script_cve_id( "CVE-2016-1952", "CVE-2016-1954", "CVE-2016-1957", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1964", "CVE-2016-1966", "CVE-2016-1974", "CVE-2016-1950", "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for thunderbird USN-2934-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Bob Clary, Christoph Diehl, Christian Holler,
  Andrew McCreight, Daniel Holbert, Jesse Ruderman, and Randell Jesup discovered
  multiple memory safety issues in Thunderbird. If a user were tricked in to
  opening a specially crafted message, an attacker could potentially exploit these
  to cause a denial of service via application crash, or execute arbitrary code
  with the privileges of the user invoking Thunderbird. (CVE-2016-1952)

  Nicolas Golubovic discovered that CSP violation reports can be used to
  overwrite local files. If a user were tricked in to opening a specially
  crafted website in a browsing context with addon signing disabled and
  unpacked addons installed, an attacker could potentially exploit this to
  gain additional privileges. (CVE-2016-1954)

  Jose Martinez and Romina Santillan discovered a memory leak in
  libstagefright during MPEG4 video file processing in some circumstances.
  If a user were tricked in to opening a specially crafted website in a
  browsing context, an attacker could potentially exploit this to cause a
  denial of service via memory exhaustion. (CVE-2016-1957)

  A use-after-free was discovered in the HTML5 string parser. If a user were
  tricked in to opening a specially crafted website in a browsing context, an
  attacker could potentially exploit this to cause a denial of service via
  application crash, or execute arbitrary code with the privileges of the user
  invoking Thunderbird. (CVE-2016-1960)

  A use-after-free was discovered in the SetBody function of HTMLDocument.
  If a user were tricked in to opening a specially crafted website in a
  browsing context, an attacker could potentially exploit this to cause a
  denial of service via application crash, or execute arbitrary code with
  the privileges of the user invoking Thunderbird. (CVE-2016-1961)

  Nicolas Gr&#233 goire discovered a use-after-free during XML transformations.
  If a user were tricked in to opening a specially crafted website in a
  browsing context, an attacker could potentially exploit this to cause a
  denial of service via application crash, or execute arbitrary code with
  the privileges of the user invoking Thunderbird. (CVE-2016-1964)

  A memory corruption issue was discovered in the NPAPI subsystem. If
  a user were tricked in to opening a specially crafted website in a
  browsing context with a malicious plugin installed, an attacker could
  potentially exploit this to cause a denial of service via application
  crash, or execute arbitrary code with the privileges of the user invoking
  Thunderbird. (CVE-2016-1966)

  Ronald Crane discovered an out-of-bounds read following a failed
  ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2934-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2934-1/" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.7.2+build1-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.7.2+build1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:38.7.2+build1-0ubuntu0.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

