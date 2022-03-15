if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853093" );
	script_version( "2021-08-13T14:00:52+0000" );
	script_cve_id( "CVE-2019-12921", "CVE-2020-10938" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 14:00:52 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-31 06:15:00 +0000 (Tue, 31 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-04-01 03:03:21 +0000 (Wed, 01 Apr 2020)" );
	script_name( "openSUSE: Security Advisory for GraphicsMagick (openSUSE-SU-2020:0416-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0416-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00049.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the openSUSE-SU-2020:0416-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for GraphicsMagick fixes the following issues:

  - CVE-2019-12921: Fixed an issue where text filename components
  potentially coulf have allowed reading of arbitrary files via
  TranslateTextEx (boo#1167208).

  - CVE-2020-10938: Fixed an integer overflow and resultant heap-based
  buffer overflow in HuffmanDecodeImages (boo#1167623).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-416=1" );
	script_tag( name: "affected", value: "'GraphicsMagick' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick", rpm: "GraphicsMagick~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-debuginfo", rpm: "GraphicsMagick-debuginfo~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-debugsource", rpm: "GraphicsMagick-debugsource~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-devel", rpm: "GraphicsMagick-devel~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-Q16-12", rpm: "libGraphicsMagick++-Q16-12~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-Q16-12-debuginfo", rpm: "libGraphicsMagick++-Q16-12-debuginfo~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick++-devel", rpm: "libGraphicsMagick++-devel~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick-Q16-3", rpm: "libGraphicsMagick-Q16-3~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick-Q16-3-debuginfo", rpm: "libGraphicsMagick-Q16-3-debuginfo~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagick3-config", rpm: "libGraphicsMagick3-config~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagickWand-Q16-2", rpm: "libGraphicsMagickWand-Q16-2~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libGraphicsMagickWand-Q16-2-debuginfo", rpm: "libGraphicsMagickWand-Q16-2-debuginfo~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-GraphicsMagick", rpm: "perl-GraphicsMagick~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-GraphicsMagick-debuginfo", rpm: "perl-GraphicsMagick-debuginfo~1.3.29~lp151.4.17.1", rls: "openSUSELeap15.1" ) )){
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

