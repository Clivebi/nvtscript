if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842883" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-09-15 05:46:35 +0200 (Thu, 15 Sep 2016)" );
	script_cve_id( "CVE-2016-1854", "CVE-2016-1856", "CVE-2016-1857", "CVE-2016-1858", "CVE-2016-1859", "CVE-2016-4583", "CVE-2016-4585", "CVE-2016-4586", "CVE-2016-4588", "CVE-2016-4589", "CVE-2016-4590", "CVE-2016-4591", "CVE-2016-4622", "CVE-2016-4623", "CVE-2016-4624", "CVE-2016-4651" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for webkit2gtk USN-3079-1" );
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
	script_xref( name: "USN", value: "3079-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3079-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "libjavascriptcoregtk-4.0-18:i386", ver: "2.12.5-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libjavascriptcoregtk-4.0-18:amd64", ver: "2.12.5-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libwebkit2gtk-4.0-37:i386", ver: "2.12.5-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libwebkit2gtk-4.0-37:amd64", ver: "2.12.5-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

