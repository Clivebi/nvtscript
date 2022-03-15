if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852801" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2019-18277" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-12-04 03:02:56 +0000 (Wed, 04 Dec 2019)" );
	script_name( "openSUSE: Security Advisory for haproxy (openSUSE-SU-2019:2626-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2626-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-12/msg00016.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'haproxy'
  package(s) announced via the openSUSE-SU-2019:2626-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for haproxy to version 2.0.10 fixes the following issues:

  HAProxy was updated to 2.0.10

  Security issues fixed:

  - CVE-2019-18277: Fixed a potential HTTP smuggling in messages with
  transfer-encoding header missing the 'chunked' (bsc#1154980).

  - Fixed an improper handling of headers which could have led to injecting
  LFs in H2-to-H1 transfers creating new attack space (bsc#1157712)

  - Fixed an issue where HEADER frames in idle streams are not rejected and
  thus trying to decode them HAPrpxy crashes (bsc#1157714).

  Other issue addressed:

  - Macro change in the spec file (bsc#1082318)

This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2626=1" );
	script_tag( name: "affected", value: "'haproxy' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "haproxy", rpm: "haproxy~2.0.10+git0.ac198b92~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "haproxy-debuginfo", rpm: "haproxy-debuginfo~2.0.10+git0.ac198b92~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "haproxy-debugsource", rpm: "haproxy-debugsource~2.0.10+git0.ac198b92~lp150.2.16.1", rls: "openSUSELeap15.0" ) )){
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

