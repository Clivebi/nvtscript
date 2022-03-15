if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.3210.1" );
	script_cve_id( "CVE-2021-3622" );
	script_tag( name: "creation_date", value: "2021-09-24 07:14:32 +0000 (Fri, 24 Sep 2021)" );
	script_version( "2021-09-24T07:14:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 07:14:32 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-09-24 07:14:17 +0000 (Fri, 24 Sep 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:3210-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:3210-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20213210-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'hivex' package(s) announced via the SUSE-SU-2021:3210-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for hivex fixes the following issues:

CVE-2021-3622: Fixed stack overflow due to recursive call of
 _get_children() (bsc#1189060)." );
	script_tag( name: "affected", value: "'hivex' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5." );
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "hivex-debuginfo", rpm: "hivex-debuginfo~1.3.10~5.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hivex-debugsource", rpm: "hivex-debugsource~1.3.10~5.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhivex0", rpm: "libhivex0~1.3.10~5.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhivex0-debuginfo", rpm: "libhivex0-debuginfo~1.3.10~5.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Win-Hivex", rpm: "perl-Win-Hivex~1.3.10~5.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Win-Hivex-debuginfo", rpm: "perl-Win-Hivex-debuginfo~1.3.10~5.7.1", rls: "SLES12.0SP5" ) )){
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

