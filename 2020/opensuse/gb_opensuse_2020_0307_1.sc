if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853062" );
	script_version( "2021-08-13T03:00:58+0000" );
	script_cve_id( "CVE-2019-12528", "CVE-2020-8449", "CVE-2020-8450", "CVE-2020-8517" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 03:00:58 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 20:47:00 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-03-07 04:00:26 +0000 (Sat, 07 Mar 2020)" );
	script_name( "openSUSE: Security Advisory for squid (openSUSE-SU-2020:0307-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0307-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00012.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid'
  package(s) announced via the openSUSE-SU-2020:0307-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for squid to version 4.10 fixes the following issues:

  Security issues fixed:

  - CVE-2019-12528: Fixed an information disclosure flaw in the FTP gateway
  (bsc#1162689).

  - CVE-2020-8449: Fixed a buffer overflow when squid is acting as
  reverse-proxy (bsc#1162687).

  - CVE-2020-8450: Fixed a buffer overflow when squid is acting as
  reverse-proxy (bsc#1162687).

  - CVE-2020-8517: Fixed a buffer overflow in ext_lm_group_acl when
  processing NTLM Authentication credentials (bsc#1162691).

  Non-security issue fixed:

  - Improved cache handling with chunked responses.

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-307=1" );
	script_tag( name: "affected", value: "'squid' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "squid", rpm: "squid~4.10~lp151.2.11.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "squid-debuginfo", rpm: "squid-debuginfo~4.10~lp151.2.11.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "squid-debugsource", rpm: "squid-debugsource~4.10~lp151.2.11.1", rls: "openSUSELeap15.1" ) )){
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

