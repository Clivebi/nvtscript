if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852651" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-1010006" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-16 02:01:00 +0000 (Fri, 16 Aug 2019)" );
	script_name( "openSUSE: Security Advisory for evince (openSUSE-SU-2019:1908-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1908-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00046.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'evince'
  package(s) announced via the openSUSE-SU-2019:1908-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for evince fixes the following issues:

  - CVE-2019-1010006: Fixed a buffer overflow in
  backend/tiff/tiff-document.c (bsc#1141619).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1908=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1908=1" );
	script_tag( name: "affected", value: "'evince' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "evince-lang", rpm: "evince-lang~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince", rpm: "evince~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-debuginfo", rpm: "evince-debuginfo~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-debugsource", rpm: "evince-debugsource~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-devel", rpm: "evince-devel~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-comicsdocument", rpm: "evince-plugin-comicsdocument~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "<br>evince-plugin-comicsdocument-debuginfo", rpm: "<br>evince-plugin-comicsdocument-debuginfo~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-djvudocument", rpm: "evince-plugin-djvudocument~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-djvudocument-debuginfo", rpm: "evince-plugin-djvudocument-debuginfo~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-dvidocument", rpm: "evince-plugin-dvidocument~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-dvidocument-debuginfo", rpm: "evince-plugin-dvidocument-debuginfo~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-pdfdocument", rpm: "evince-plugin-pdfdocument~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-pdfdocument-debuginfo", rpm: "evince-plugin-pdfdocument-debuginfo~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-psdocument", rpm: "evince-plugin-psdocument~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-psdocument-debuginfo", rpm: "evince-plugin-psdocument-debuginfo~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-tiffdocument", rpm: "evince-plugin-tiffdocument~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-tiffdocument-debuginfo", rpm: "evince-plugin-tiffdocument-debuginfo~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-xpsdocument", rpm: "evince-plugin-xpsdocument~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-xpsdocument-debuginfo", rpm: "evince-plugin-xpsdocument-debuginfo~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libevdocument3-4", rpm: "libevdocument3-4~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libevdocument3-4-debuginfo", rpm: "libevdocument3-4-debuginfo~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libevview3-3", rpm: "libevview3-3~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libevview3-3-debuginfo", rpm: "libevview3-3-debuginfo~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nautilus-evince", rpm: "nautilus-evince~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nautilus-evince-debuginfo", rpm: "nautilus-evince-debuginfo~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-EvinceDocument-3_0", rpm: "typelib-1_0-EvinceDocument-3_0~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-EvinceView-3_0", rpm: "typelib-1_0-EvinceView-3_0~3.26.0+20180128.1bd86963~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
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

