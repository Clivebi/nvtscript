if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852732" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2018-19540", "CVE-2018-19541" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-29 22:15:00 +0000 (Fri, 29 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-10-08 02:00:47 +0000 (Tue, 08 Oct 2019)" );
	script_name( "openSUSE: Security Advisory for jasper (openSUSE-SU-2019:2279-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2279-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-10/msg00025.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jasper'
  package(s) announced via the openSUSE-SU-2019:2279-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for jasper fixes the following issues:

  Security issues fixed:

  - CVE-2018-19540: Fixed  a heap based overflow in jas_icctxtdesc_input
  (bsc#1117508).

  - CVE-2018-19541: Fix heap based overread in jas_image_depalettize
  (bsc#1117507).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2279=1" );
	script_tag( name: "affected", value: "'jasper' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "jasper", rpm: "jasper~2.0.14~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jasper-debuginfo", rpm: "jasper-debuginfo~2.0.14~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jasper-debugsource", rpm: "jasper-debugsource~2.0.14~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper-devel", rpm: "libjasper-devel~2.0.14~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper4", rpm: "libjasper4~2.0.14~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper4-debuginfo", rpm: "libjasper4-debuginfo~2.0.14~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper4-32bit", rpm: "libjasper4-32bit~2.0.14~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper4-32bit-debuginfo", rpm: "libjasper4-32bit-debuginfo~2.0.14~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
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

