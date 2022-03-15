if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843983" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2018-16877", "CVE-2018-16878", "CVE-2019-3885" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-27 18:29:00 +0000 (Mon, 27 May 2019)" );
	script_tag( name: "creation_date", value: "2019-04-24 02:00:54 +0000 (Wed, 24 Apr 2019)" );
	script_name( "Ubuntu Update for pacemaker USN-3952-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU18\\.10|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "3952-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-April/004859.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pacemaker'
  package(s) announced via the USN-3952-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jan Pokorný discovered that Pacemaker incorrectly handled client-server
authentication. A local attacker could possibly use this issue to escalate
privileges. (CVE-2018-16877)

Jan Pokorný discovered that Pacemaker incorrectly handled certain
verifications. A local attacker could possibly use this issue to cause a
denial of service. (CVE-2018-16878)

Jan Pokorný discovered that Pacemaker incorrectly handled certain memory
operations. A local attacker could possibly use this issue to obtain
sensitive information in log outputs. This issue only applied to Ubuntu
18.04 LTS, Ubuntu 18.10, and Ubuntu 19.04. (CVE-2019-3885)" );
	script_tag( name: "affected", value: "'pacemaker' package(s) on Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "pacemaker", ver: "1.1.18-0ubuntu1.1", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "pacemaker", ver: "1.1.18-2ubuntu1.18.10.1", rls: "UBUNTU18.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "pacemaker", ver: "1.1.14-2ubuntu1.6", rls: "UBUNTU16.04 LTS" ) )){
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

