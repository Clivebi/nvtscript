if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843689" );
	script_version( "2021-06-04T11:00:20+0000" );
	script_cve_id( "CVE-2018-1071", "CVE-2018-1083" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-04 11:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-01 07:15:00 +0000 (Tue, 01 Dec 2020)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:07:09 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for zsh USN-3608-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3608-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3608-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zsh'
  package(s) announced via the USN-3608-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Richard Maciel Costa discovered that Zsh incorrectly handled certain
inputs. An attacker could possibly use this to cause a denial of
service. (CVE-2018-1071)

It was discovered that Zsh incorrectly handled certain files. An
attacker could possibly use this to execute arbitrary code.
(CVE-2018-1083)" );
	script_tag( name: "affected", value: "zsh on Ubuntu 17.10,
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
	if(( res = isdpkgvuln( pkg: "zsh", ver: "5.0.2-3ubuntu6.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "zsh", ver: "5.2-5ubuntu1.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "zsh", ver: "5.1.1-1ubuntu2.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

