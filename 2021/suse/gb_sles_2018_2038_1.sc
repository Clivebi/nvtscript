if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2038.1" );
	script_cve_id( "CVE-2015-3243" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-31 19:07:00 +0000 (Mon, 31 Jul 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2038-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2038-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182038-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rsyslog' package(s) announced via the SUSE-SU-2018:2038-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rsyslog fixes the following issues:
The following security vulnerability was addressed:
CVE-2015-3243: Make sure that log files are not created world-readable
(bsc#935393)" );
	script_tag( name: "affected", value: "'rsyslog' package(s) on SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "rsyslog", rpm: "rsyslog~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-debuginfo", rpm: "rsyslog-debuginfo~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-debugsource", rpm: "rsyslog-debugsource~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-diag-tools", rpm: "rsyslog-diag-tools~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-diag-tools-debuginfo", rpm: "rsyslog-diag-tools-debuginfo~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-doc", rpm: "rsyslog-doc~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-gssapi", rpm: "rsyslog-module-gssapi~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-gssapi-debuginfo", rpm: "rsyslog-module-gssapi-debuginfo~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-gtls", rpm: "rsyslog-module-gtls~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-gtls-debuginfo", rpm: "rsyslog-module-gtls-debuginfo~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-mysql", rpm: "rsyslog-module-mysql~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-mysql-debuginfo", rpm: "rsyslog-module-mysql-debuginfo~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-pgsql", rpm: "rsyslog-module-pgsql~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-pgsql-debuginfo", rpm: "rsyslog-module-pgsql-debuginfo~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-relp", rpm: "rsyslog-module-relp~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-relp-debuginfo", rpm: "rsyslog-module-relp-debuginfo~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-snmp", rpm: "rsyslog-module-snmp~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-snmp-debuginfo", rpm: "rsyslog-module-snmp-debuginfo~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-udpspoof", rpm: "rsyslog-module-udpspoof~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-udpspoof-debuginfo", rpm: "rsyslog-module-udpspoof-debuginfo~8.24.0~3.3.1", rls: "SLES12.0SP3" ) )){
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

