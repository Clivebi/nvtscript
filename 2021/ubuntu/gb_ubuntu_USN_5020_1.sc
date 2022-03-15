if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.845008" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_cve_id( "CVE-2021-31799", "CVE-2021-31810", "CVE-2021-32066" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-10 13:03:00 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-22 03:00:29 +0000 (Thu, 22 Jul 2021)" );
	script_name( "Ubuntu: Security Advisory for ruby2.7 (USN-5020-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-5020-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-July/006115.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby2.7'
  package(s) announced via the USN-5020-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Ruby incorrectly handled certain inputs.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2021-31799)

It was discovered that Ruby incorrectly handled certain inputs.
An attacker could possibly use this issue to conduct
port scans and service banner extractions. This issue only affected
Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, Ubuntu 20.10, and Ubuntu 21.04. (CVE-2021-31810)

It was discovered that Ruby incorrectly handled certain inputs.
An attacker could possibly use this issue to perform
man-in-the-middle attackers to bypass the TLS protection.
(CVE-2021-32066)" );
	script_tag( name: "affected", value: "'ruby2.7' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libruby2.7", ver: "2.7.0-5ubuntu1.5", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby2.7", ver: "2.7.0-5ubuntu1.5", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libruby2.5", ver: "2.5.1-1ubuntu1.10", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby2.5", ver: "2.5.1-1ubuntu1.10", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libruby2.7", ver: "2.7.1-3ubuntu1.4", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ruby2.7", ver: "2.7.1-3ubuntu1.4", rls: "UBUNTU20.10" ) )){
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

