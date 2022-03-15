if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853428" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2017-17789" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-13 18:36:00 +0000 (Wed, 13 Mar 2019)" );
	script_tag( name: "creation_date", value: "2020-09-14 03:00:46 +0000 (Mon, 14 Sep 2020)" );
	script_name( "openSUSE: Security Advisory for gimp (openSUSE-SU-2020:1420-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:1420-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00034.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gimp'
  package(s) announced via the openSUSE-SU-2020:1420-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gimp fixes the following issue:

  - CVE-2017-17789: Fix heap buffer overflow in PSP importer (bsc#1073627).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1420=1" );
	script_tag( name: "affected", value: "'gimp' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "gimp", rpm: "gimp~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gimp-debuginfo", rpm: "gimp-debuginfo~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gimp-debugsource", rpm: "gimp-debugsource~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gimp-devel", rpm: "gimp-devel~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gimp-devel-debuginfo", rpm: "gimp-devel-debuginfo~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gimp-plugin-aa", rpm: "gimp-plugin-aa~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gimp-plugin-aa-debuginfo", rpm: "gimp-plugin-aa-debuginfo~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gimp-plugins-python", rpm: "gimp-plugins-python~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gimp-plugins-python-debuginfo", rpm: "gimp-plugins-python-debuginfo~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgimp-2_0-0", rpm: "libgimp-2_0-0~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgimp-2_0-0-debuginfo", rpm: "libgimp-2_0-0-debuginfo~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgimpui-2_0-0", rpm: "libgimpui-2_0-0~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgimpui-2_0-0-debuginfo", rpm: "libgimpui-2_0-0-debuginfo~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgimp-2_0-0-32bit", rpm: "libgimp-2_0-0-32bit~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgimp-2_0-0-32bit-debuginfo", rpm: "libgimp-2_0-0-32bit-debuginfo~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgimpui-2_0-0-32bit", rpm: "libgimpui-2_0-0-32bit~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgimpui-2_0-0-32bit-debuginfo", rpm: "libgimpui-2_0-0-32bit-debuginfo~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gimp-lang", rpm: "gimp-lang~2.8.22~lp151.5.3.1", rls: "openSUSELeap15.1" ) )){
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

