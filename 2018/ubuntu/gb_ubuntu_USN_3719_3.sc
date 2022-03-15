if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843642" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-28 08:19:24 +0200 (Fri, 28 Sep 2018)" );
	script_cve_id( "CVE-2018-14350", "CVE-2018-14352", "CVE-2018-14354", "CVE-2018-14359", "CVE-2018-14358", "CVE-2018-14353", "CVE-2018-14357", "CVE-2018-14355", "CVE-2018-14356", "CVE-2018-14351", "CVE-2018-14362", "CVE-2018-14349" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-20 01:39:00 +0000 (Wed, 20 May 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for mutt USN-3719-3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mutt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "insight", value: "USN-3719-1 fixed vulnerabilities in Mutt.
Unfortunately, the fixes were not correctly applied to the packaging for Mutt in
Ubuntu 16.04 LTS. This update corrects the oversight.

We apologize for the inconvenience.

Original advisory details:

It was discovered that Mutt incorrectly handled certain requests.
An attacker could possibly use this to execute arbitrary code.
(CVE-2018-14350, CVE-2018-14352, CVE-2018-14354, CVE-2018-14359,
CVE-2018-14358, CVE-2018-14353, CVE-2018-14357)

It was discovered that Mutt incorrectly handled certain inputs.
An attacker could possibly use this to access or expose sensitive
information. (CVE-2018-14355, CVE-2018-14356, CVE-2018-14351,
CVE-2018-14362, CVE-2018-14349)" );
	script_tag( name: "affected", value: "mutt on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3719-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3719-3/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "mutt", ver: "1.5.24-1ubuntu0.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mutt-patched", ver: "1.5.24-1ubuntu0.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

