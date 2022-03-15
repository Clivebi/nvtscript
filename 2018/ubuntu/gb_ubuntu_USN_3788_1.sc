if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843783" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_cve_id( "CVE-2015-5700", "CVE-2018-17407" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-15 16:11:00 +0000 (Thu, 15 Nov 2018)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:18:48 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for texlive-bin USN-3788-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3788-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3788-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'texlive-bin'
  package(s) announced via the USN-3788-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jakub Wilk discovered that Tex Live incorrectly handled certain files.
An attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 14.04 LTS. (CVE-2015-5700)

It was discovered that Tex Live incorrectly handled certain files.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2018-17407)" );
	script_tag( name: "affected", value: "texlive-bin on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
	if(( res = isdpkgvuln( pkg: "texlive-binaries", ver: "2013.20130729.30972-2ubuntu0.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "texlive-binaries", ver: "2017.20170613.44572-8ubuntu0.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "texlive-binaries", ver: "2015.20160222.37495-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

