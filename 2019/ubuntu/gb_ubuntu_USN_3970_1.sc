if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843998" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2019-3839" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 14:31:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-05-09 02:00:36 +0000 (Thu, 09 May 2019)" );
	script_name( "Ubuntu Update for ghostscript USN-3970-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.10|UBUNTU19\\.04|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "3970-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3970-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghostscript'
  package(s) announced via the USN-3970-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Ghostscript incorrectly handled certain PostScript
files. If a user or automated system were tricked into processing a
specially crafted file, a remote attacker could possibly use this issue to
access arbitrary files, execute arbitrary code, or cause a denial of
service." );
	script_tag( name: "affected", value: "'ghostscript' package(s) on Ubuntu 19.04, Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
report = "";
if(release == "UBUNTU18.10"){
	if(!isnull( res = isdpkgvuln( pkg: "ghostscript", ver: "9.26~dfsg+0-0ubuntu0.18.10.9", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libgs9", ver: "9.26~dfsg+0-0ubuntu0.18.10.9", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "ghostscript", ver: "9.26~dfsg+0-0ubuntu7.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libgs9", ver: "9.26~dfsg+0-0ubuntu7.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "ghostscript", ver: "9.26~dfsg+0-0ubuntu0.18.04.9", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libgs9", ver: "9.26~dfsg+0-0ubuntu0.18.04.9", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "ghostscript", ver: "9.26~dfsg+0-0ubuntu0.16.04.9", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libgs9", ver: "9.26~dfsg+0-0ubuntu0.16.04.9", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

