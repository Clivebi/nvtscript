if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853188" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2019-13508" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-30 00:15:00 +0000 (Sat, 30 May 2020)" );
	script_tag( name: "creation_date", value: "2020-05-30 03:00:37 +0000 (Sat, 30 May 2020)" );
	script_name( "openSUSE: Security Advisory for freetds (openSUSE-SU-2020:0741-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0741-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00067.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freetds'
  package(s) announced via the openSUSE-SU-2020:0741-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for freetds to 1.1.36 fixes the following issues:

  Security issue fixed:

  - CVE-2019-13508: Fixed a heap overflow that could have been caused by
  malicious servers sending UDT types over protocol version 5.0
  (bsc#1141132).

  Non-security issues fixed:

  - Enabled Kerberos support

  - Version update to 1.1.36:

  * Default TDS protocol version is now 'auto'

  * Improved UTF-8 performances

  * TDS Pool Server is enabled

  * MARS support is enabled

  * NTLMv2 is enabled

  * See NEWS and ChangeLog for a complete list of changes

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-741=1" );
	script_tag( name: "affected", value: "'freetds' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "freetds-config", rpm: "freetds-config~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetds-debuginfo", rpm: "freetds-debuginfo~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetds-debugsource", rpm: "freetds-debugsource~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetds-devel", rpm: "freetds-devel~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetds-doc", rpm: "freetds-doc~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetds-tools", rpm: "freetds-tools~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetds-tools-debuginfo", rpm: "freetds-tools-debuginfo~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libct4", rpm: "libct4~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libct4-debuginfo", rpm: "libct4-debuginfo~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsybdb5", rpm: "libsybdb5~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsybdb5-debuginfo", rpm: "libsybdb5-debuginfo~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdsodbc0", rpm: "libtdsodbc0~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdsodbc0-debuginfo", rpm: "libtdsodbc0-debuginfo~1.1.36~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
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

