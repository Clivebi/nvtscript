if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844919" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2020-28007", "CVE-2020-28008", "CVE-2020-28009", "CVE-2020-28010", "CVE-2020-28011", "CVE-2020-28012", "CVE-2020-28013", "CVE-2020-28014", "CVE-2020-28015", "CVE-2020-28016", "CVE-2020-28017", "CVE-2020-28018", "CVE-2020-28019", "CVE-2020-28020", "CVE-2020-28021", "CVE-2020-28022", "CVE-2020-28023", "CVE-2020-28024", "CVE-2020-28025", "CVE-2020-28026", "CVE-2021-27216" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-10 16:13:00 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-05 03:00:52 +0000 (Wed, 05 May 2021)" );
	script_name( "Ubuntu: Security Advisory for exim4 (USN-4934-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4934-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-May/006001.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exim4'
  package(s) announced via the USN-4934-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Exim contained multiple security issues. An attacker
could use these issues to cause a denial of service, execute arbitrary
code remotely, obtain sensitive information, or escalate local privileges." );
	script_tag( name: "affected", value: "'exim4' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "exim4-base", ver: "4.93-13ubuntu1.5", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.93-13ubuntu1.5", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.93-13ubuntu1.5", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "exim4-base", ver: "4.90.1-1ubuntu1.8", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.90.1-1ubuntu1.8", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.90.1-1ubuntu1.8", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "exim4-base", ver: "4.94-7ubuntu1.2", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.94-7ubuntu1.2", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.94-7ubuntu1.2", rls: "UBUNTU20.10" ) )){
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

