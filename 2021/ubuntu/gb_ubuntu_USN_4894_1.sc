if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844882" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2020-27918", "CVE-2020-29623", "CVE-2021-1765", "CVE-2021-1789", "CVE-2021-1799", "CVE-2021-1801", "CVE-2021-1870" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-02 13:21:00 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-03-30 03:00:33 +0000 (Tue, 30 Mar 2021)" );
	script_name( "Ubuntu: Security Advisory for webkit2gtk (USN-4894-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4894-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-March/005951.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk'
  package(s) announced via the USN-4894-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A large number of security issues were discovered in the WebKitGTK Web and
JavaScript engines. If a user were tricked into viewing a malicious
website, a remote attacker could exploit a variety of issues related to web
browser security, including cross-site scripting attacks, denial of service
attacks, and arbitrary code execution." );
	script_tag( name: "affected", value: "'webkit2gtk' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libjavascriptcoregtk-4.0-18", ver: "2.30.6-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libwebkit2gtk-4.0-37", ver: "2.30.6-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libjavascriptcoregtk-4.0-18", ver: "2.30.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libwebkit2gtk-4.0-37", ver: "2.30.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU20.10"){
	if(!isnull( res = isdpkgvuln( pkg: "libjavascriptcoregtk-4.0-18", ver: "2.30.6-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libwebkit2gtk-4.0-37", ver: "2.30.6-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
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

