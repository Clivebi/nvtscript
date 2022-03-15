if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844916" );
	script_version( "2021-08-18T06:00:55+0000" );
	script_cve_id( "CVE-2021-3497", "CVE-2021-3498" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-18 06:00:55 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-27 16:48:00 +0000 (Tue, 27 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-30 03:00:51 +0000 (Fri, 30 Apr 2021)" );
	script_name( "Ubuntu: Security Advisory for gst-plugins-good1.0 (USN-4928-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4928-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-April/005993.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gst-plugins-good1.0'
  package(s) announced via the USN-4928-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that GStreamer Good Plugins incorrectly handled certain files.
An attacker could possibly use this issue to cause access sensitive information
or cause a crash. (CVE-2021-3497)

It was discovered that GStreamer Good Plugins incorrectly handled certain files.
An attacker could possibly use this issue to execute arbitrary code or cause
a crash. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu
20.10. (CVE-2021-3498)" );
	script_tag( name: "affected", value: "'gst-plugins-good1.0' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good", ver: "1.16.2-1ubuntu2.1", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good", ver: "1.14.5-0ubuntu1~18.04.2", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good", ver: "1.8.3-1ubuntu0.5", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good", ver: "1.18.0-1ubuntu1.1", rls: "UBUNTU20.10" ) )){
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
