if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0813.1" );
	script_cve_id( "CVE-2018-11805", "CVE-2020-1930", "CVE-2020-1931" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-02 04:15:00 +0000 (Sun, 02 Feb 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0813-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0813-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200813-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spamassassin' package(s) announced via the SUSE-SU-2020:0813-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for spamassassin fixes the following issues:

Security issues fixed:

CVE-2018-11805: Fixed an issue with delimiter handling in rule files
 related to is_regexp_valid() (bsc#1118987).

CVE-2020-1930: Fixed an issue with rule configuration (.cf) files which
 can be configured to run system commands (bsc#1162197).

CVE-2020-1931: Fixed an issue with rule configuration (.cf) files which
 can be configured to run system commands with warnings (bsc#1162200).

Non-security issue fixed:

Altering hash requires restarting loop (bsc#862963)." );
	script_tag( name: "affected", value: "'spamassassin' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "perl-Mail-SpamAssassin", rpm: "perl-Mail-SpamAssassin~3.4.2~7.9.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Mail-SpamAssassin-Plugin-iXhash2", rpm: "perl-Mail-SpamAssassin-Plugin-iXhash2~2.05~7.9.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spamassassin", rpm: "spamassassin~3.4.2~7.9.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spamassassin-debuginfo", rpm: "spamassassin-debuginfo~3.4.2~7.9.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spamassassin-debugsource", rpm: "spamassassin-debugsource~3.4.2~7.9.1", rls: "SLES15.0" ) )){
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

