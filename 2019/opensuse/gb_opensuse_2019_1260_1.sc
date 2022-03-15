if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852445" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2018-13440" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-13 14:23:00 +0000 (Mon, 13 Apr 2020)" );
	script_tag( name: "creation_date", value: "2019-04-24 02:01:19 +0000 (Wed, 24 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for audiofile (openSUSE-SU-2019:1260-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1260-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00087.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'audiofile'
  package(s) announced via the openSUSE-SU-2019:1260-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for audiofile fixes the following issues:

  Security issue fixed:

  - CVE-2018-13440: Return AF_FAIL instead of causing NULL pointer
  dereferences later (bsc#1100523).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1260=1" );
	script_tag( name: "affected", value: "'audiofile' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "audiofile", rpm: "audiofile~0.3.6~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "audiofile-debuginfo", rpm: "audiofile-debuginfo~0.3.6~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "audiofile-debugsource", rpm: "audiofile-debugsource~0.3.6~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "audiofile-devel", rpm: "audiofile-devel~0.3.6~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "audiofile-doc", rpm: "audiofile-doc~0.3.6~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaudiofile1", rpm: "libaudiofile1~0.3.6~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaudiofile1-debuginfo", rpm: "libaudiofile1-debuginfo~0.3.6~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "audiofile-devel-32bit", rpm: "audiofile-devel-32bit~0.3.6~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaudiofile1-32bit", rpm: "libaudiofile1-32bit~0.3.6~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaudiofile1-32bit-debuginfo", rpm: "libaudiofile1-32bit-debuginfo~0.3.6~lp150.7.1", rls: "openSUSELeap15.0" ) )){
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

