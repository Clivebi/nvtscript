if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0097.1" );
	script_cve_id( "CVE-2011-3922" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:29 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-07 18:43:00 +0000 (Thu, 07 May 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0097-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0097-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120097-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libqt4' package(s) announced via the SUSE-SU-2012:0097-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A stack-based buffer overflow in the glyph handling of libqt4's harfbuzz has been fixed. CVE-2011-3922 has been assigned to this issue.

Security Issuereference:

 * CVE-2011-3922
>" );
	script_tag( name: "affected", value: "'libqt4' package(s) on SUSE Linux Enterprise Desktop 11 SP1, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Software Development Kit 11 SP1." );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libQtWebKit4-32bit", rpm: "libQtWebKit4-32bit~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQtWebKit4", rpm: "libQtWebKit4~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQtWebKit4-x86", rpm: "libQtWebKit4-x86~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-32bit", rpm: "libqt4-32bit~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4", rpm: "libqt4~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-qt3support-32bit", rpm: "libqt4-qt3support-32bit~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-qt3support", rpm: "libqt4-qt3support~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-qt3support-x86", rpm: "libqt4-qt3support-x86~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-32bit", rpm: "libqt4-sql-32bit~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql", rpm: "libqt4-sql~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-sqlite", rpm: "libqt4-sql-sqlite~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-sql-x86", rpm: "libqt4-sql-x86~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x11-32bit", rpm: "libqt4-x11-32bit~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x11", rpm: "libqt4-x11~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x11-x86", rpm: "libqt4-x11-x86~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt4-x86", rpm: "libqt4-x86~4.6.3~5.12.1", rls: "SLES11.0SP1" ) )){
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

