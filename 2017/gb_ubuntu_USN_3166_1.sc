if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843008" );
	script_version( "2021-09-13T13:34:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 13:34:59 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-11 05:38:31 +0100 (Wed, 11 Jan 2017)" );
	script_cve_id( "CVE-2016-4613", "CVE-2016-4657", "CVE-2016-4666", "CVE-2016-4707", "CVE-2016-4728", "CVE-2016-4733", "CVE-2016-4734", "CVE-2016-4735", "CVE-2016-4759", "CVE-2016-4760", "CVE-2016-4761", "CVE-2016-4762", "CVE-2016-4764", "CVE-2016-4765", "CVE-2016-4767", "CVE-2016-4768", "CVE-2016-4769", "CVE-2016-7578" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-13 13:40:00 +0000 (Wed, 13 Mar 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for webkit2gtk USN-3166-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A large number of security issues were
  discovered in the WebKitGTK+ Web and JavaScript engines. If a user were tricked
  into viewing a malicious website, a remote attacker could exploit a variety of
  issues related to web browser security, including cross-site scripting attacks,
  denial of service attacks, and arbitrary code execution." );
	script_tag( name: "affected", value: "webkit2gtk on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3166-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3166-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libjavascriptcoregtk-4.0-18", ver: "2.14.2-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libwebkit2gtk-4.0-37", ver: "2.14.2-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

