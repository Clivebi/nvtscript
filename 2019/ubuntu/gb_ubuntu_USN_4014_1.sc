if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844047" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2019-12450" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-06-11 02:01:09 +0000 (Tue, 11 Jun 2019)" );
	script_name( "Ubuntu Update for glib2.0 USN-4014-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.10|UBUNTU19\\.04|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4014-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-June/004953.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glib2.0'
  package(s) announced via the USN-4014-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that GLib incorrectly handled certain files.
An attacker could possibly use this issue to access sensitive information." );
	script_tag( name: "affected", value: "'glib2.0' package(s) on Ubuntu 19.04, Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-0", ver: "2.58.1-2ubuntu0.1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-bin", ver: "2.58.1-2ubuntu0.1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-dev", ver: "2.58.1-2ubuntu0.1", rls: "UBUNTU18.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-0", ver: "2.60.0-1ubuntu0.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-bin", ver: "2.60.0-1ubuntu0.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-dev", ver: "2.60.0-1ubuntu0.1", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-0", ver: "2.56.4-0ubuntu0.18.04.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-bin", ver: "2.56.4-0ubuntu0.18.04.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-dev", ver: "2.56.4-0ubuntu0.18.04.3", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-0", ver: "2.48.2-0ubuntu4.2", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-bin", ver: "2.48.2-0ubuntu4.2", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-dev", ver: "2.48.2-0ubuntu4.2", rls: "UBUNTU16.04 LTS" ) )){
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

