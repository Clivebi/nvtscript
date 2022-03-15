if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853517" );
	script_version( "2021-08-13T14:00:52+0000" );
	script_cve_id( "CVE-2019-16707" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 14:00:52 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-19 01:15:00 +0000 (Tue, 19 Nov 2019)" );
	script_tag( name: "creation_date", value: "2020-10-25 04:00:48 +0000 (Sun, 25 Oct 2020)" );
	script_name( "openSUSE: Security Advisory for hunspell (openSUSE-SU-2020:1719-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1719-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00052.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'hunspell'
  package(s) announced via the openSUSE-SU-2020:1719-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for hunspell fixes the following issues:

  - CVE-2019-16707: Fixed an invalid read in SuggestMgr:leftcommonsubstring
  (bsc#1151867).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1719=1" );
	script_tag( name: "affected", value: "'hunspell' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "hunspell", rpm: "hunspell~1.6.2~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hunspell-debuginfo", rpm: "hunspell-debuginfo~1.6.2~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hunspell-debugsource", rpm: "hunspell-debugsource~1.6.2~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hunspell-devel", rpm: "hunspell-devel~1.6.2~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hunspell-tools", rpm: "hunspell-tools~1.6.2~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hunspell-tools-debuginfo", rpm: "hunspell-tools-debuginfo~1.6.2~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhunspell-1_6-0", rpm: "libhunspell-1_6-0~1.6.2~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhunspell-1_6-0-debuginfo", rpm: "libhunspell-1_6-0-debuginfo~1.6.2~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hunspell-devel-32bit", rpm: "hunspell-devel-32bit~1.6.2~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhunspell-1_6-0-32bit", rpm: "libhunspell-1_6-0-32bit~1.6.2~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhunspell-1_6-0-32bit-debuginfo", rpm: "libhunspell-1_6-0-32bit-debuginfo~1.6.2~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
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

