if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.2827.1" );
	script_cve_id( "CVE-2019-20919" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-06 18:15:00 +0000 (Tue, 06 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:2827-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1|SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:2827-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20202827-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-DBI' package(s) announced via the SUSE-SU-2020:2827-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for perl-DBI fixes the following issues:

CVE-2019-20919: Fixed a NULL profile dereference in dbi_profile
 (bsc#1176764)." );
	script_tag( name: "affected", value: "'perl-DBI' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "perl-DBI", rpm: "perl-DBI~1.639~3.11.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-DBI-debuginfo", rpm: "perl-DBI-debuginfo~1.639~3.11.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-DBI-debugsource", rpm: "perl-DBI-debugsource~1.639~3.11.1", rls: "SLES15.0SP1" ) )){
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "perl-DBI", rpm: "perl-DBI~1.639~3.11.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-DBI-debuginfo", rpm: "perl-DBI-debuginfo~1.639~3.11.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-DBI-debugsource", rpm: "perl-DBI-debugsource~1.639~3.11.1", rls: "SLES15.0" ) )){
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
