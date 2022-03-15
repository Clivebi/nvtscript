if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843949" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2018-18506", "CVE-2019-9788", "CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9795", "CVE-2019-9796", "CVE-2019-9810", "CVE-2019-9813", "CVE-2019-9793" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-13 10:29:00 +0000 (Mon, 13 May 2019)" );
	script_tag( name: "creation_date", value: "2019-04-03 06:39:10 +0000 (Wed, 03 Apr 2019)" );
	script_name( "Ubuntu Update for thunderbird USN-3927-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU14\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU18\\.10|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "3927-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3927-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the USN-3927-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Thunderbird
allowed PAC files to specify that requests to localhost are sent through
the proxy to another server. If proxy auto-detection is enabled, an attacker
could potentially exploit this to conduct attacks on local services and tools.
(CVE-2018-18506)

Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted website in a browsing context,
an attacker could potentially exploit these to cause a denial of service,
or execute arbitrary code. (CVE-2019-9788, CVE-2019-9790, CVE-2019-9791,
CVE-2019-9792, CVE-2019-9795, CVE-2019-9796, CVE-2019-9810, CVE-2019-9813)

A mechanism was discovered that removes some bounds checking for string,
array, or typed array accesses if Spectre mitigations have been disabled.
If a user were tricked in to opening a specially crafted website in a
browsing context with Spectre mitigations disabled, an attacker could
potentially exploit this to cause a denial of service, or execute
arbitrary code. (CVE-2019-9793)" );
	script_tag( name: "affected", value: "'thunderbird' package(s) on Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS, Ubuntu 14.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "thunderbird", ver: "1:60.6.1+build2-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "thunderbird", ver: "1:60.6.1+build2-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "thunderbird", ver: "1:60.6.1+build2-0ubuntu0.18.10.1", rls: "UBUNTU18.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "thunderbird", ver: "1:60.6.1+build2-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
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

