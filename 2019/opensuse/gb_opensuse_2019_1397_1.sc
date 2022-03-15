if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852498" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2017-15134", "CVE-2017-15135", "CVE-2018-10850", "CVE-2018-10935", "CVE-2018-14624" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-15 21:29:00 +0000 (Wed, 15 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-16 02:01:24 +0000 (Thu, 16 May 2019)" );
	script_name( "openSUSE: Security Advisory for 389-ds (openSUSE-SU-2019:1397-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1397-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00033.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the '389-ds'
  package(s) announced via the openSUSE-SU-2019:1397-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for 389-ds fixes the following issues:

  The following security vulnerabilities were addressed:

  - CVE-2018-10850: Fixed a race condition on reference counter that would
  lead to a denial of service using persistent search (bsc#1096368)

  - CVE-2017-15134: Fixed a remote denial of service via search filters in
  slapi_filter_sprintf in slapd/util.c (bsc#1076530)

  - CVE-2017-15135: Fixed authentication bypass due to lack of size check in
  slapi_ct_memcmp function in ch_malloc.c (bsc#1076530)

  - CVE-2018-10935: Fixed an issue that allowed users to cause a crash via
  ldapsearch with server side sorts (bsc#1105606)

  - CVE-2018-14624: The lock controlling the error log was not correctly
  used when re-opening the log file in log__error_emergency(), allowing an
  attacker to send a flood of modifications to a very large DN, which
  could have caused slapd to crash (bsc#1106699).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1397=1" );
	script_tag( name: "affected", value: "'389-ds' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "389-ds", rpm: "389-ds~1.4.0.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-debuginfo", rpm: "389-ds-debuginfo~1.4.0.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-debugsource", rpm: "389-ds-debugsource~1.4.0.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-devel", rpm: "389-ds-devel~1.4.0.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-snmp", rpm: "389-ds-snmp~1.4.0.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "389-ds-snmp-debuginfo", rpm: "389-ds-snmp-debuginfo~1.4.0.3~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
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

