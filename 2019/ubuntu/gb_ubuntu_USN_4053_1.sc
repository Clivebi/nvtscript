if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844087" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2019-12447", "CVE-2019-12448", "CVE-2019-12449", "CVE-2019-12795" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-08 00:15:00 +0000 (Mon, 08 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-07-10 02:00:31 +0000 (Wed, 10 Jul 2019)" );
	script_name( "Ubuntu Update for gvfs USN-4053-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.10|UBUNTU19\\.04|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4053-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-July/005004.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gvfs'
  package(s) announced via the USN-4053-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that GVfs incorrectly handled the admin backend. Files
created or moved by the admin backend could end up with the wrong ownership
information, contrary to expectations. This issue only affected Ubuntu
18.04 LTS, Ubuntu 18.10, and Ubuntu 19.04. (CVE-2019-12447, CVE-2019-12448,
CVE-2019-12449)

It was discovered that GVfs incorrectly handled authentication on its
private D-Bus socket. A local attacker could possibly connect to this
socket and issue D-Bus calls. (CVE-2019-12795)" );
	script_tag( name: "affected", value: "'gvfs' package(s) on Ubuntu 19.04, Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "gvfs", ver: "1.38.1-0ubuntu1.3.2", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "gvfs-backends", ver: "1.38.1-0ubuntu1.3.2", rls: "UBUNTU18.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "gvfs", ver: "1.40.1-1ubuntu0.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "gvfs-backends", ver: "1.40.1-1ubuntu0.1", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "gvfs", ver: "1.36.1-0ubuntu1.3.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "gvfs-backends", ver: "1.36.1-0ubuntu1.3.3", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "gvfs", ver: "1.28.2-1ubuntu1~16.04.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "gvfs-backends", ver: "1.28.2-1ubuntu1~16.04.3", rls: "UBUNTU16.04 LTS" ) )){
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

