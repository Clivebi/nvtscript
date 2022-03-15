if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852631" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2018-20843" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-15 23:15:00 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-07-22 02:01:27 +0000 (Mon, 22 Jul 2019)" );
	script_name( "openSUSE: Security Advisory for expat (openSUSE-SU-2019:1777-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1777-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-07/msg00039.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'expat'
  package(s) announced via the openSUSE-SU-2019:1777-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for expat fixes the following issues:

  Security issue fixed:

  - CVE-2018-20843: Fixed a denial of service triggered by high resource
  consumption in the XML parser when XML names contain a large amount of
  colons (bsc#1139937).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1777=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1777=1" );
	script_tag( name: "affected", value: "'expat' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "expat", rpm: "expat~2.2.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debuginfo", rpm: "expat-debuginfo~2.2.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debugsource", rpm: "expat-debugsource~2.2.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat-devel", rpm: "libexpat-devel~2.2.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1", rpm: "libexpat1~2.2.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-debuginfo", rpm: "libexpat1-debuginfo~2.2.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-32bit-debuginfo", rpm: "expat-32bit-debuginfo~2.2.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat-devel-32bit", rpm: "libexpat-devel-32bit~2.2.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-32bit", rpm: "libexpat1-32bit~2.2.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-32bit-debuginfo", rpm: "libexpat1-32bit-debuginfo~2.2.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

