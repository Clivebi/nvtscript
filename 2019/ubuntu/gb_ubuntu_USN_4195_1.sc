if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844243" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2019-2910", "CVE-2019-2911", "CVE-2019-2914", "CVE-2019-2920", "CVE-2019-2922", "CVE-2019-2923", "CVE-2019-2924", "CVE-2019-2938", "CVE-2019-2946", "CVE-2019-2948", "CVE-2019-2950", "CVE-2019-2957", "CVE-2019-2960", "CVE-2019-2963", "CVE-2019-2966", "CVE-2019-2967", "CVE-2019-2968", "CVE-2019-2969", "CVE-2019-2974", "CVE-2019-2982", "CVE-2019-2991", "CVE-2019-2993", "CVE-2019-2997", "CVE-2019-2998", "CVE-2019-3003", "CVE-2019-3004", "CVE-2019-3009", "CVE-2019-3011", "CVE-2019-3018" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-11 20:15:00 +0000 (Mon, 11 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-11-19 03:01:02 +0000 (Tue, 19 Nov 2019)" );
	script_name( "Ubuntu Update for mysql-8.0 USN-4195-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.10|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4195-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-November/005213.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-8.0'
  package(s) announced via the USN-4195-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.18 in Ubuntu 19.10. Ubuntu 16.04 LTS, Ubuntu
18.04 LTS, and Ubuntu 19.04 have been updated to MySQL 5.7.28.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes." );
	script_tag( name: "affected", value: "'mysql-8.0' package(s) on Ubuntu 19.10, Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.28-0ubuntu0.18.04.4", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "mysql-server-8.0", ver: "8.0.18-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.28-0ubuntu0.19.04.2", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "mysql-server-5.7", ver: "5.7.28-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) )){
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

