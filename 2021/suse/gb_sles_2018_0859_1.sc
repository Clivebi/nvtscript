if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0859.1" );
	script_cve_id( "CVE-2017-11462", "CVE-2018-5729", "CVE-2018-5730" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:46 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-21 15:47:00 +0000 (Tue, 21 Jan 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0859-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0859-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180859-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5' package(s) announced via the SUSE-SU-2018:0859-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for krb5 fixes several issues.
This security issue was fixed:
- CVE-2017-11462: Prevent automatic security context deletion to prevent
 double-free (bsc#1056995).
- CVE-2018-5729: Null pointer dereference in kadmind or DN container check
 bypass by supplying special crafted data (bsc#1083926).
- CVE-2018-5730: DN container check bypass by supplying special crafted
 data (bsc#1083927).
This non-security issue was fixed:
- Avoid indefinite polling in KDC communication. (bsc#970696)" );
	script_tag( name: "affected", value: "'krb5' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.6.3~133.49.113.7.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-32bit", rpm: "krb5-32bit~1.6.3~133.49.113.7.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-apps-clients", rpm: "krb5-apps-clients~1.6.3~133.49.113.7.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-apps-servers", rpm: "krb5-apps-servers~1.6.3~133.49.113.7.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-client", rpm: "krb5-client~1.6.3~133.49.113.7.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.6.3~133.49.113.7.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-x86", rpm: "krb5-x86~1.6.3~133.49.113.7.1", rls: "SLES11.0SP4" ) )){
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

