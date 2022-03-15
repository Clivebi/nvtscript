if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852235" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2019-3500" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-06 18:29:00 +0000 (Mon, 06 May 2019)" );
	script_tag( name: "creation_date", value: "2019-01-14 04:00:47 +0100 (Mon, 14 Jan 2019)" );
	script_name( "openSUSE: Security Advisory for aria2 (openSUSE-SU-2019:0050-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.3|openSUSELeap15\\.0)" );
	script_xref( name: "openSUSE-SU", value: "2019:0050-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-01/msg00016.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aria2'
  package(s) announced via the openSUSE-SU-2019:0050-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for aria2 fixes the following security issue:

  - CVE-2019-3500: Metadata and potential password leaks via --log=
  (boo#1120488)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-50=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-50=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-50=1" );
	script_tag( name: "affected", value: "aria2 on openSUSE Leap 42.3, openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "aria2", rpm: "aria2~1.24.0~4.4.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2-debuginfo", rpm: "aria2-debuginfo~1.24.0~4.4.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2-debugsource", rpm: "aria2-debugsource~1.24.0~4.4.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2-devel", rpm: "aria2-devel~1.24.0~4.4.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaria2-0", rpm: "libaria2-0~1.24.0~4.4.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaria2-0-debuginfo", rpm: "libaria2-0-debuginfo~1.24.0~4.4.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2-lang", rpm: "aria2-lang~1.24.0~4.4.1", rls: "openSUSELeap42.3" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "aria2", rpm: "aria2~1.33.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2-debuginfo", rpm: "aria2-debuginfo~1.33.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2-debugsource", rpm: "aria2-debugsource~1.33.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2-devel", rpm: "aria2-devel~1.33.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaria2-0", rpm: "libaria2-0~1.33.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaria2-0-debuginfo", rpm: "libaria2-0-debuginfo~1.33.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2-lang", rpm: "aria2-lang~1.33.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
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

