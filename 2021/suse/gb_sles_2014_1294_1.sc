if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.1294.1" );
	script_cve_id( "CVE-2014-3634", "CVE-2014-3683" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-10-18 03:44:00 +0000 (Tue, 18 Oct 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:1294-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:1294-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20141294-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rsyslog' package(s) announced via the SUSE-SU-2014:1294-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "rsyslog has been updated to fix a remote denial of service issue:

 * Under certain configurations, a local or remote attacker able to
 send syslog messages to the server could have crashed the log server
 due to an array overread. (CVE-2014-3634, CVE-2014-3683)

Security Issues:

 * CVE-2014-3634
 * CVE-2014-3683" );
	script_tag( name: "affected", value: "'rsyslog' package(s) on SUSE Linux Enterprise Server 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "rsyslog", rpm: "rsyslog~5.10.1~0.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-diag-tools", rpm: "rsyslog-diag-tools~5.10.1~0.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-doc", rpm: "rsyslog-doc~5.10.1~0.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-gssapi", rpm: "rsyslog-module-gssapi~5.10.1~0.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-gtls", rpm: "rsyslog-module-gtls~5.10.1~0.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-mysql", rpm: "rsyslog-module-mysql~5.10.1~0.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-pgsql", rpm: "rsyslog-module-pgsql~5.10.1~0.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-relp", rpm: "rsyslog-module-relp~5.10.1~0.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-snmp", rpm: "rsyslog-module-snmp~5.10.1~0.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-module-udpspoof", rpm: "rsyslog-module-udpspoof~5.10.1~0.11.1", rls: "SLES11.0SP3" ) )){
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

