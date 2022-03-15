if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3909.1" );
	script_cve_id( "CVE-2018-10915" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-17 19:15:00 +0000 (Mon, 17 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3909-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1|SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3909-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183909-1/" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/9.4/static/release-9-4-18.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql94' package(s) announced via the SUSE-SU-2018:3909-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql94 to 9.4.19 fixes the following security issue:
CVE-2018-10915: libpq failed to properly reset its internal state
 between connections. If an affected version of libpq was used with
 'host' or 'hostaddr' connection parameters from untrusted input,
 attackers could have bypassed client-side connection security features,
 obtain access to higher privileged connections or potentially cause
 other impact SQL injection, by causing the PQescape() functions to
 malfunction (bsc#1104199).

A dump/restore is not required for this update unless you use the functions query_to_xml, cursor_to_xml, cursor_to_xmlschema,
query_to_xmlschema, and query_to_xml_and_xmlschema. In this case please see the first entry of [link moved to references]" );
	script_tag( name: "affected", value: "'postgresql94' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE OpenStack Cloud 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "postgresql94", rpm: "postgresql94~9.4.19~21.22.7", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-contrib", rpm: "postgresql94-contrib~9.4.19~21.22.7", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-contrib-debuginfo", rpm: "postgresql94-contrib-debuginfo~9.4.19~21.22.7", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-debuginfo", rpm: "postgresql94-debuginfo~9.4.19~21.22.7", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-debugsource", rpm: "postgresql94-debugsource~9.4.19~21.22.7", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-docs", rpm: "postgresql94-docs~9.4.19~21.22.7", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-server", rpm: "postgresql94-server~9.4.19~21.22.7", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-server-debuginfo", rpm: "postgresql94-server-debuginfo~9.4.19~21.22.7", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "postgresql94", rpm: "postgresql94~9.4.19~21.22.7", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-contrib", rpm: "postgresql94-contrib~9.4.19~21.22.7", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-contrib-debuginfo", rpm: "postgresql94-contrib-debuginfo~9.4.19~21.22.7", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-debuginfo", rpm: "postgresql94-debuginfo~9.4.19~21.22.7", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-debugsource", rpm: "postgresql94-debugsource~9.4.19~21.22.7", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-docs", rpm: "postgresql94-docs~9.4.19~21.22.7", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-server", rpm: "postgresql94-server~9.4.19~21.22.7", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-server-debuginfo", rpm: "postgresql94-server-debuginfo~9.4.19~21.22.7", rls: "SLES12.0SP1" ) )){
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "postgresql94", rpm: "postgresql94~9.4.19~21.22.7", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-contrib", rpm: "postgresql94-contrib~9.4.19~21.22.7", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-contrib-debuginfo", rpm: "postgresql94-contrib-debuginfo~9.4.19~21.22.7", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-debuginfo", rpm: "postgresql94-debuginfo~9.4.19~21.22.7", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-debugsource", rpm: "postgresql94-debugsource~9.4.19~21.22.7", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-docs", rpm: "postgresql94-docs~9.4.19~21.22.7", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-server", rpm: "postgresql94-server~9.4.19~21.22.7", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-server-debuginfo", rpm: "postgresql94-server-debuginfo~9.4.19~21.22.7", rls: "SLES12.0SP2" ) )){
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

