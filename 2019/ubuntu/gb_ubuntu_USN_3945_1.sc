if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843974" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_cve_id( "CVE-2019-8320", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325" );
	script_tag( name: "cvss_base", value: "8.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-16 15:15:00 +0000 (Sun, 16 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-12 02:00:22 +0000 (Fri, 12 Apr 2019)" );
	script_name( "Ubuntu Update for ruby2.5 USN-3945-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU14\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU18\\.10|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "3945-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3945-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'ruby2.5' package(s) announced via the USN-3945-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
  is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Ruby incorrectly
handled certain RubyGems.
An attacker could possibly use this issue to execute arbitrary
commands. (CVE-2019-8320)

It was discovered that Ruby incorrectly handled certain inputs.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2019-8321, CVE-2019-8322, CVE-2019-8323, CVE-2019-8324, CVE-2019-8325)" );
	script_tag( name: "affected", value: "'ruby2.5' package(s) on Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS, Ubuntu 14.04 LTS." );
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
if(release == "UBUNTU14.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libruby1.9.1", ver: "1.9.3.484-2ubuntu1.14", rls: "UBUNTU14.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libruby2.0", ver: "2.0.0.484-1ubuntu2.13", rls: "UBUNTU14.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby1.9.1", ver: "1.9.3.484-2ubuntu1.14", rls: "UBUNTU14.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby1.9.3", ver: "1.9.3.484-2ubuntu1.14", rls: "UBUNTU14.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby2.0", ver: "2.0.0.484-1ubuntu2.13", rls: "UBUNTU14.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libruby2.5", ver: "2.5.1-1ubuntu1.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby2.5", ver: "2.5.1-1ubuntu1.2", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU18.10"){
	if(!isnull( res = isdpkgvuln( pkg: "libruby2.5", ver: "2.5.1-5ubuntu4.3", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby2.5", ver: "2.5.1-5ubuntu4.3", rls: "UBUNTU18.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libruby2.3", ver: "2.3.1-2~16.04.12", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby2.3", ver: "2.3.1-2~16.04.12", rls: "UBUNTU16.04 LTS" ) )){
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

