if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852331" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2019-8358" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-19 16:02:00 +0000 (Tue, 19 Feb 2019)" );
	script_tag( name: "creation_date", value: "2019-03-06 04:09:19 +0100 (Wed, 06 Mar 2019)" );
	script_name( "openSUSE: Security Advisory for hiawatha (openSUSE-SU-2019:0294-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0294-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-03/msg00004.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'hiawatha'
  package(s) announced via the openSUSE-SU-2019:0294-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for hiawatha to version 10.8.4 fixes the following issue:

  Security issue fixed:

  - CVE-2019-8358: Fixed a vulnerability which allowed a remote attacker to
  perform directory traversal when AllowDotFiles was enabled (bsc#1125751).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-294=1" );
	script_tag( name: "affected", value: "hiawatha on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "hiawatha", rpm: "hiawatha~10.8.4~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hiawatha-debuginfo", rpm: "hiawatha-debuginfo~10.8.4~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hiawatha-debugsource", rpm: "hiawatha-debugsource~10.8.4~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hiawatha-letsencrypt", rpm: "hiawatha-letsencrypt~10.8.4~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
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

