if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0865.1" );
	script_cve_id( "CVE-2017-11468" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:46 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-18 19:15:00 +0000 (Fri, 18 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0865-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0865-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180865-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'docker-distribution' package(s) announced via the SUSE-SU-2018:0865-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for docker-distribution fixes the following issues:
Security issues fixed:
- CVE-2017-11468: Fixed a denial of service (memory consumption) via the
 manifest endpoint (bsc#1049850).
Bug fixes:
- bsc#1083474: docker-distirbution-registry overwrites configuration file
 with update.
- bsc#1033172: Garbage collector needed - or kindly release
 docker-distribution-registry in Version 2.4.
- Add SuSEfirewall2 service file for TCP port 5000." );
	script_tag( name: "affected", value: "'docker-distribution' package(s) on SUSE Linux Enterprise Module for Containers 12." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "docker-distribution-registry", rpm: "docker-distribution-registry~2.6.2~13.6.1", rls: "SLES12.0" ) )){
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

