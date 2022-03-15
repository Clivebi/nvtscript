if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0505.1" );
	script_cve_id( "CVE-2016-1238" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-16 11:29:00 +0000 (Sun, 16 Dec 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0505-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0505-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190505-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'amavisd-new' package(s) announced via the SUSE-SU-2019:0505-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for amavisd-new fixes the following issues:

wmavisd-new was updated to version 2.11.1 (bsc#1123389):
removed a trailing dot element from @INC, as a workaround for a perl
 vulnerability CVE-2016-1238 (bsc#987887)

amavis-services: bumping up syslog level from LOG_NOTICE to LOG_ERR for
 a message 'PID went away', and removed redundant newlines from
 some log messages

safe_decode() and safe_decode_utf8(): avoid warning messages 'Use of
 uninitialized value in subroutine entry' in Encode::MIME::Header when
 the $check argument is undefined

@sa_userconf_maps has been extended to allow loading of per-recipient
 (or per-policy bank, or global) SpamAssassin configuration set from
 LDAP. For consistency with SQL a @sa_userconf_maps entry prefixed with
 'ldap:' will load SpamAssassin configuration set using the
 load_scoreonly_ldap() method, a patch by Atanas Karashenski

add some Sanesecurity.Foxhole false positives to the default list
 @virus_name_to_spam_score_maps

updated some comments

Update amavis-milter to version 2.6.1:
Fixed bug when creating amavisd-new policy bank names" );
	script_tag( name: "affected", value: "'amavisd-new' package(s) on SUSE Linux Enterprise Module for Basesystem 15." );
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
	if(!isnull( res = isrpmvuln( pkg: "amavisd-new", rpm: "amavisd-new~2.11.1~6.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "amavisd-new-debuginfo", rpm: "amavisd-new-debuginfo~2.11.1~6.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "amavisd-new-debugsource", rpm: "amavisd-new-debugsource~2.11.1~6.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "amavisd-new-docs", rpm: "amavisd-new-docs~2.11.1~6.3.1", rls: "SLES15.0" ) )){
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

