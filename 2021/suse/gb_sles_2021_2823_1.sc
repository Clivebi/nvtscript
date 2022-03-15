if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2823.1" );
	script_cve_id( "CVE-2021-22930", "CVE-2021-22931", "CVE-2021-22939", "CVE-2021-3672" );
	script_tag( name: "creation_date", value: "2021-08-25 02:24:18 +0000 (Wed, 25 Aug 2021)" );
	script_version( "2021-08-26T02:26:42+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 02:26:42 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-24 13:54:00 +0000 (Tue, 24 Aug 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2823-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2823-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212823-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs10' package(s) announced via the SUSE-SU-2021:2823-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs10 fixes the following issues:

CVE-2021-3672: Fixed missing input validation on hostnames (bsc#1188881).

CVE-2021-22930: Fixed use after free on close http2 on stream canceling
 (bsc#1188917).

CVE-2021-22939: Fixed incomplete validation of rejectUnauthorized
 parameter (bsc#1189369).

CVE-2021-22931: Fixed improper handling of untypical characters in
 domain names (bsc#1189370)." );
	script_tag( name: "affected", value: "'nodejs10' package(s) on SUSE Linux Enterprise Module for Web Scripting 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs10", rpm: "nodejs10~10.24.1~1.42.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-debuginfo", rpm: "nodejs10-debuginfo~10.24.1~1.42.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-devel", rpm: "nodejs10-devel~10.24.1~1.42.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-docs", rpm: "nodejs10-docs~10.24.1~1.42.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm10", rpm: "npm10~10.24.1~1.42.2", rls: "SLES12.0" ) )){
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

