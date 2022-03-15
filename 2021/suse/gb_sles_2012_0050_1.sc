if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0050.1" );
	script_cve_id( "CVE-2011-1526", "CVE-2011-4862" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:29 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-09 14:48:00 +0000 (Tue, 09 Feb 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0050-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP3|SLES10\\.0SP4|SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0050-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120050-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Kerberos 5' package(s) announced via the SUSE-SU-2012:0050-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of krb5 fixes two security issues.

 * CVE-2011-4862: A remote code execution in the kerberized telnet daemon was fixed. (This only affects the ktelnetd from the krb5-appl RPM, not the regular telnetd supplied by SUSE.)
 * CVE-2011-1526 / MITKRB5-SA-2011-005: Fixed krb5 ftpd unauthorized file access problems.

Security Issue reference:

 * CVE-2011-4862
>" );
	script_tag( name: "affected", value: "'Kerberos 5' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Desktop 11 SP1, SUSE Linux Enterprise Server 10 SP3, SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Software Development Kit 11 SP1." );
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
if(release == "SLES10.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.4.3~19.49.49.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-32bit", rpm: "krb5-32bit~1.4.3~19.49.49.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-apps-clients", rpm: "krb5-apps-clients~1.4.3~19.49.49.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-apps-servers", rpm: "krb5-apps-servers~1.4.3~19.49.49.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-client", rpm: "krb5-client~1.4.3~19.49.49.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.4.3~19.49.49.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel-32bit", rpm: "krb5-devel-32bit~1.4.3~19.49.49.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.4.3~19.49.49.1", rls: "SLES10.0SP3" ) )){
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.4.3~19.49.49.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-32bit", rpm: "krb5-32bit~1.4.3~19.49.49.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-64bit", rpm: "krb5-64bit~1.4.3~19.49.49.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-apps-clients", rpm: "krb5-apps-clients~1.4.3~19.49.49.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-apps-servers", rpm: "krb5-apps-servers~1.4.3~19.49.49.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-client", rpm: "krb5-client~1.4.3~19.49.49.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.4.3~19.49.49.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel-32bit", rpm: "krb5-devel-32bit~1.4.3~19.49.49.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel-64bit", rpm: "krb5-devel-64bit~1.4.3~19.49.49.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.4.3~19.49.49.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-x86", rpm: "krb5-x86~1.4.3~19.49.49.1", rls: "SLES10.0SP4" ) )){
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.6.3~133.48.48.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-32bit", rpm: "krb5-32bit~1.6.3~133.48.48.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-apps-clients", rpm: "krb5-apps-clients~1.6.3~133.48.48.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-apps-servers", rpm: "krb5-apps-servers~1.6.3~133.48.48.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-client", rpm: "krb5-client~1.6.3~133.48.48.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.6.3~133.48.48.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-x86", rpm: "krb5-x86~1.6.3~133.48.48.1", rls: "SLES11.0SP1" ) )){
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

