if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842427" );
	script_version( "2019-12-18T09:57:42+0000" );
	script_tag( name: "last_modification", value: "2019-12-18 09:57:42 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-09-04 08:15:21 +0200 (Fri, 04 Sep 2015)" );
	script_cve_id( "CVE-2012-4428", "CVE-2015-5177" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openslp-dfsg USN-2730-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openslp-dfsg'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Georgi Geshev discovered that OpenSLP
incorrectly handled processing certain service requests. A remote attacker
could possibly use this issue to cause OpenSLP to crash, resulting in a denial
of service. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2012-4428)

Qinghao Tang discovered that OpenSLP incorrectly handled processing certain
messages. A remote attacker could possibly use this issue to cause
OpenSLP to crash, resulting in a denial of service. (CVE-2015-5177)" );
	script_tag( name: "affected", value: "openslp-dfsg on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2730-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2730-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libslp1", ver: "1.2.1-9ubuntu0.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libslp1", ver: "1.2.1-7.8ubuntu1.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

