if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.845021" );
	script_version( "2021-08-24T09:58:36+0000" );
	script_cve_id( "CVE-2021-3672" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 09:58:36 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 03:00:28 +0000 (Wed, 11 Aug 2021)" );
	script_name( "Ubuntu: Security Advisory for c-ares (USN-5034-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "Advisory-ID", value: "USN-5034-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-August/006136.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'c-ares'
  package(s) announced via the USN-5034-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Philipp Jeitner and Haya Shulman discovered that c-ares incorrectly
validated certain hostnames returned by DNS servers. A remote attacker
could possibly use this issue to perform Domain Hijacking attacks." );
	script_tag( name: "affected", value: "'c-ares' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libc-ares2", ver: "1.14.0-1ubuntu0.1", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libc-ares2", ver: "1.15.0-1ubuntu0.1", rls: "UBUNTU20.04 LTS" ) )){
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

