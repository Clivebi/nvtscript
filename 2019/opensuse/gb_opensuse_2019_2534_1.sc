if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852779" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2019-14869" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-09 13:12:00 +0000 (Fri, 09 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-11-21 03:00:46 +0000 (Thu, 21 Nov 2019)" );
	script_name( "openSUSE: Security Advisory for ghostscript (openSUSE-SU-2019:2534-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2534-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00049.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghostscript'
  package(s) announced via the openSUSE-SU-2019:2534-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ghostscript fixes the following issues:

  - CVE-2019-14869: Fixed a possible  dSAFER escape which could have allowed
  an attacker to gain high privileges by a specially crafted Postscript
  code (bsc#1156275).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2534=1" );
	script_tag( name: "affected", value: "'ghostscript' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "ghostscript", rpm: "ghostscript~9.27~lp150.2.26.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-debuginfo", rpm: "ghostscript-debuginfo~9.27~lp150.2.26.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-debugsource", rpm: "ghostscript-debugsource~9.27~lp150.2.26.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-devel", rpm: "ghostscript-devel~9.27~lp150.2.26.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-mini", rpm: "ghostscript-mini~9.27~lp150.2.26.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-mini-debuginfo", rpm: "ghostscript-mini-debuginfo~9.27~lp150.2.26.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-mini-debugsource", rpm: "ghostscript-mini-debugsource~9.27~lp150.2.26.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-mini-devel", rpm: "ghostscript-mini-devel~9.27~lp150.2.26.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-x11", rpm: "ghostscript-x11~9.27~lp150.2.26.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-x11-debuginfo", rpm: "ghostscript-x11-debuginfo~9.27~lp150.2.26.1", rls: "openSUSELeap15.0" ) )){
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

