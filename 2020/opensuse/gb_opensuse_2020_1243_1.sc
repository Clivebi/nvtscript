if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853374" );
	script_version( "2021-08-13T12:00:53+0000" );
	script_cve_id( "CVE-2020-14349", "CVE-2020-14350" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 12:00:53 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-18 12:15:00 +0000 (Fri, 18 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-08-23 03:01:04 +0000 (Sun, 23 Aug 2020)" );
	script_name( "openSUSE: Security Advisory for postgresql12 (openSUSE-SU-2020:1243-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:1243-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00050.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql12'
  package(s) announced via the openSUSE-SU-2020:1243-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql12 fixes the following issues:

  - update to 12.4:

  * CVE-2020-14349, bsc#1175193: Set a secure search_path in logical
  replication walsenders and apply workers

  * CVE-2020-14350, bsc#1175194: Make contrib modules' installation
  scripts more secure.

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1243=1" );
	script_tag( name: "affected", value: "'postgresql12' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo", rpm: "libecpg6-debuginfo~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo", rpm: "libpq5-debuginfo~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12", rpm: "postgresql12~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-contrib", rpm: "postgresql12-contrib~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-contrib-debuginfo", rpm: "postgresql12-contrib-debuginfo~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-debuginfo", rpm: "postgresql12-debuginfo~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-debugsource", rpm: "postgresql12-debugsource~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-devel", rpm: "postgresql12-devel~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-devel-debuginfo", rpm: "postgresql12-devel-debuginfo~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-llvmjit", rpm: "postgresql12-llvmjit~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-llvmjit-debuginfo", rpm: "postgresql12-llvmjit-debuginfo~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plperl", rpm: "postgresql12-plperl~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plperl-debuginfo", rpm: "postgresql12-plperl-debuginfo~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plpython", rpm: "postgresql12-plpython~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plpython-debuginfo", rpm: "postgresql12-plpython-debuginfo~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-pltcl", rpm: "postgresql12-pltcl~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-pltcl-debuginfo", rpm: "postgresql12-pltcl-debuginfo~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server", rpm: "postgresql12-server~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server-debuginfo", rpm: "postgresql12-server-debuginfo~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server-devel", rpm: "postgresql12-server-devel~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server-devel-debuginfo", rpm: "postgresql12-server-devel-debuginfo~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-test", rpm: "postgresql12-test~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-docs", rpm: "postgresql12-docs~12.4~lp151.6.1", rls: "openSUSELeap15.1" ) )){
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

