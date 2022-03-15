if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852906" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2017-18594", "CVE-2018-15173" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-26 12:15:00 +0000 (Thu, 26 Sep 2019)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:44:11 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for nmap (openSUSE-SU-2019:2200-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2200-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00075.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nmap'
  package(s) announced via the openSUSE-SU-2019:2200-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nmap fixes the following issues:

  Security issue fixed:

  - CVE-2017-18594: Fixed a denial of service condition due to a double free
  when an SSH connection fails. (bsc#1148742)

  Non-security issue fixed:

  - Fixed a regression in the version scanner caused, by the fix for
  CVE-2018-15173. (bsc#1135350)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2200=1" );
	script_tag( name: "affected", value: "'nmap' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "ncat", rpm: "ncat~7.70~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncat-debuginfo", rpm: "ncat-debuginfo~7.70~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ndiff", rpm: "ndiff~7.70~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nmap", rpm: "nmap~7.70~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nmap-debuginfo", rpm: "nmap-debuginfo~7.70~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nmap-debugsource", rpm: "nmap-debugsource~7.70~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nping", rpm: "nping~7.70~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nping-debuginfo", rpm: "nping-debuginfo~7.70~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zenmap", rpm: "zenmap~7.70~lp151.3.9.1", rls: "openSUSELeap15.1" ) )){
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

