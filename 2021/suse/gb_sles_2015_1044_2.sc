if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1044.2" );
	script_cve_id( "CVE-2012-5519", "CVE-2015-1158", "CVE-2015-1159" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-23 01:29:00 +0000 (Sat, 23 Sep 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1044-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1044-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151044-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cups154' package(s) announced via the SUSE-SU-2015:1044-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following issues are fixed by this update:
* CVE-2012-5519: privilege escalation via cross-site scripting and bad
 print job submission used to replace cupsd.conf on server (bsc#924208).
* CVE-2015-1158: Improper Update of Reference Count
* CVE-2015-1159: Cross-Site Scripting" );
	script_tag( name: "affected", value: "'cups154' package(s) on SUSE Linux Enterprise Module for Legacy Software 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "cups154", rpm: "cups154~1.5.4~9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups154-client", rpm: "cups154-client~1.5.4~9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups154-client-debuginfo", rpm: "cups154-client-debuginfo~1.5.4~9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups154-debuginfo", rpm: "cups154-debuginfo~1.5.4~9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups154-debugsource", rpm: "cups154-debugsource~1.5.4~9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups154-filters", rpm: "cups154-filters~1.5.4~9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups154-filters-debuginfo", rpm: "cups154-filters-debuginfo~1.5.4~9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups154-libs", rpm: "cups154-libs~1.5.4~9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups154-libs-debuginfo", rpm: "cups154-libs-debuginfo~1.5.4~9.1", rls: "SLES12.0" ) )){
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

