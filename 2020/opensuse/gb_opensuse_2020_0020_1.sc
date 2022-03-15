if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852984" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2019-19191" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-14 01:15:00 +0000 (Tue, 14 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-14 04:01:23 +0000 (Tue, 14 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for shibboleth-sp (openSUSE-SU-2020:0020-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0020-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00017.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'shibboleth-sp'
  package(s) announced via the openSUSE-SU-2020:0020-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for shibboleth-sp fixes the following issues:

  Security issue fixed:

  - CVE-2019-19191: Fixed escalation to root by fixing ownership of log
  files (bsc#1157471).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-20=1" );
	script_tag( name: "affected", value: "'shibboleth-sp' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libshibsp-lite7", rpm: "libshibsp-lite7~2.6.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp-lite7-debuginfo", rpm: "libshibsp-lite7-debuginfo~2.6.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp7", rpm: "libshibsp7~2.6.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp7-debuginfo", rpm: "libshibsp7-debuginfo~2.6.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp", rpm: "shibboleth-sp~2.6.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-debuginfo", rpm: "shibboleth-sp-debuginfo~2.6.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-debugsource", rpm: "shibboleth-sp-debugsource~2.6.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-devel", rpm: "shibboleth-sp-devel~2.6.1~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
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

