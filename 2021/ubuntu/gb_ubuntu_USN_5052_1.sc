if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.845036" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-2386" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-16 14:35:00 +0000 (Fri, 16 Oct 2020)" );
	script_tag( name: "creation_date", value: "2021-08-26 03:00:22 +0000 (Thu, 26 Aug 2021)" );
	script_name( "Ubuntu: Security Advisory for mongodb (USN-5052-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "Advisory-ID", value: "USN-5052-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-August/006154.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mongodb'
  package(s) announced via the USN-5052-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MongoDB would fail to properly invalidate existing sessions for deleted
users. This could allow a remote authenticated attacker to gain elevated
privileges if their user account was recreated with elevated privileges." );
	script_tag( name: "affected", value: "'mongodb' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "mongodb-clients", ver: "1:3.6.3-0ubuntu1.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mongodb-server", ver: "1:3.6.3-0ubuntu1.3", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mongodb-server-core", ver: "1:3.6.3-0ubuntu1.3", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "mongodb-clients", ver: "1:3.6.9+really3.6.8+90~g8e540c0b6d-0ubuntu5.2", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mongodb-server", ver: "1:3.6.9+really3.6.8+90~g8e540c0b6d-0ubuntu5.2", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mongodb-server-core", ver: "1:3.6.9+really3.6.8+90~g8e540c0b6d-0ubuntu5.2", rls: "UBUNTU20.04 LTS" ) )){
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

