if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852586" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-11372", "CVE-2019-11373" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-25 06:29:00 +0000 (Sat, 25 May 2019)" );
	script_tag( name: "creation_date", value: "2019-06-27 02:00:45 +0000 (Thu, 27 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for libmediainfo (openSUSE-SU-2019:1629-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.3|openSUSELeap15\\.0)" );
	script_xref( name: "openSUSE-SU", value: "2019:1629-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00069.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmediainfo'
  package(s) announced via the openSUSE-SU-2019:1629-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libmediainfo fixes the following issues:

  * CVE-2019-11373: Fixed out-of-bounds read in function
  File__Analyze:Get_L8 (boo#1133156)

  * CVE-2019-11372: Fixed out-of-bounds read in function
  MediaInfoLib:File__Tags_Helper:Synched_Test (boo#1133157)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1629=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1629=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-1629=1" );
	script_tag( name: "affected", value: "'libmediainfo' package(s) on openSUSE Leap 42.3, openSUSE Leap 15.0." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo-debugsource", rpm: "libmediainfo-debugsource~0.7.96~2.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo-devel", rpm: "libmediainfo-devel~0.7.96~2.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo0", rpm: "libmediainfo0~0.7.96~2.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo0-debuginfo", rpm: "libmediainfo0-debuginfo~0.7.96~2.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo0-32bit", rpm: "libmediainfo0-32bit~0.7.96~2.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo0-debuginfo-32bit", rpm: "libmediainfo0-debuginfo-32bit~0.7.96~2.3.1", rls: "openSUSELeap42.3" ) )){
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo-debugsource", rpm: "libmediainfo-debugsource~18.03~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo-devel", rpm: "libmediainfo-devel~18.03~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo0", rpm: "libmediainfo0~18.03~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo0-debuginfo", rpm: "libmediainfo0-debuginfo~18.03~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo0-32bit", rpm: "libmediainfo0-32bit~18.03~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmediainfo0-32bit-debuginfo", rpm: "libmediainfo0-32bit-debuginfo~18.03~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

