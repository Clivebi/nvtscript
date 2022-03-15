if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852333" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2016-1238" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-16 11:29:00 +0000 (Sun, 16 Dec 2018)" );
	script_tag( name: "creation_date", value: "2019-03-07 04:12:14 +0100 (Thu, 07 Mar 2019)" );
	script_name( "openSUSE: Security Advisory for amavisd-new (openSUSE-SU-2019:0297-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0297-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-03/msg00007.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'amavisd-new'
  package(s) announced via the openSUSE-SU-2019:0297-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for amavisd-new fixes the following issues:

  Security issue fixed:

  - CVE-2016-1238: Workedaround a perl vulnerability by removing a trailing
  dot element from @INC      (bsc#987887).

  Other issues addressed:

  - update to version 2.11.1 (bsc#1123389).

  - amavis-services: bumping up syslog level from LOG_NOTICE to LOG_ERR for
  a message 'PID  pid  went away', and removed redundant newlines from
  some log messages

  - avoid warning messages 'Use of uninitialized value in subroutine entry'
  in Encode::MIME::Header when the $check argument is undefined

  - @sa_userconf_maps has been extended to allow loading of per-recipient
  (or per-policy bank, or global) SpamAssassin configuration set from
  LDAP. For consistency with SQL a @sa_userconf_maps entry prefixed with
  'ldap:' will load SpamAssassin configuration set using the
  load_scoreonly_ldap() method.

  - add some Sanesecurity.Foxhole false positives to the default list
  @virus_name_to_spam_score_maps

  - update amavis-milter to version 2.6.1:

  * Fixed a  bug when creating amavisd-new policy bank names

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-297=1" );
	script_tag( name: "affected", value: "amavisd-new on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "amavisd-new", rpm: "amavisd-new~2.11.1~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "amavisd-new-debuginfo", rpm: "amavisd-new-debuginfo~2.11.1~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "amavisd-new-debugsource", rpm: "amavisd-new-debugsource~2.11.1~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "amavisd-new-docs", rpm: "amavisd-new-docs~2.11.1~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
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

