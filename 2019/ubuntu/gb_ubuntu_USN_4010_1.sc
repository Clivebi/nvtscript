if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844043" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2019-10149" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-04 18:15:00 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "creation_date", value: "2019-06-06 02:00:49 +0000 (Thu, 06 Jun 2019)" );
	script_name( "Ubuntu Update for exim4 USN-4010-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU18\\.10)" );
	script_xref( name: "USN", value: "4010-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-June/004942.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exim4'
  package(s) announced via the USN-4010-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Exim incorrectly handled certain decoding
operations. A remote attacker could possibly use this issue to execute
arbitrary commands." );
	script_tag( name: "affected", value: "'exim4' package(s) on Ubuntu 18.10, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.90.1-1ubuntu1.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.90.1-1ubuntu1.2", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.91-6ubuntu1.1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.91-6ubuntu1.1", rls: "UBUNTU18.10" ) )){
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

