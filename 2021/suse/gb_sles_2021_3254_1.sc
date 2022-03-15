if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.3254.1" );
	script_cve_id( "CVE-2021-22116", "CVE-2021-32718", "CVE-2021-32719" );
	script_tag( name: "creation_date", value: "2021-09-30 06:47:09 +0000 (Thu, 30 Sep 2021)" );
	script_version( "2021-09-30T06:47:09+0000" );
	script_tag( name: "last_modification", value: "2021-09-30 06:47:09 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-19 20:15:00 +0000 (Mon, 19 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:3254-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:3254-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20213254-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rabbitmq-server' package(s) announced via the SUSE-SU-2021:3254-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rabbitmq-server fixes the following issues:

CVE-2021-32718: Fixed improper neutralization of script-related HTML
 tags in a web page (basic XSS) in management UI (bsc#1187818).

CVE-2021-32719: Fixed improper neutralization of script-related HTML
 tags in a web page (basic XSS) in federation management plugin
 (bsc#1187819).

CVE-2021-22116: Fixed improper input validation may lead to DoS
 (bsc#1186203).

Use /run instead of /var/run in tmpfiles.d configuration (bsc#1185075)." );
	script_tag( name: "affected", value: "'rabbitmq-server' package(s) on SUSE Linux Enterprise Module for Server Applications 15-SP2." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "erlang-rabbitmq-client", rpm: "erlang-rabbitmq-client~3.8.3~3.3.4", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rabbitmq-server", rpm: "rabbitmq-server~3.8.3~3.3.4", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rabbitmq-server-plugins", rpm: "rabbitmq-server-plugins~3.8.3~3.3.4", rls: "SLES15.0SP2" ) )){
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

