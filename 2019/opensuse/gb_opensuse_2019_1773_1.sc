if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852622" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2019-10130", "CVE-2019-10164" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-02 14:34:00 +0000 (Fri, 02 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-07-22 02:00:42 +0000 (Mon, 22 Jul 2019)" );
	script_name( "openSUSE: Security Advisory for postgresql10 (openSUSE-SU-2019:1773-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1773-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-07/msg00035.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql10'
  package(s) announced via the openSUSE-SU-2019:1773-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql10 fixes the following issues:

  Security issue fixed:

  - CVE-2019-10164: Fixed buffer-overflow vulnerabilities in SCRAM verifier
  parsing (bsc#1138034).

  - CVE-2019-10130: Prevent row-level security policies from being bypassed
  via selectivity estimators (bsc#1134689).

  Bug fixes:

  This update was imported from the SUSE:SLE-15:Update update project.
  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1773=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1773=1" );
	script_tag( name: "affected", value: "'postgresql10' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo", rpm: "libecpg6-debuginfo~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo", rpm: "libpq5-debuginfo~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10", rpm: "postgresql10~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-contrib", rpm: "postgresql10-contrib~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-contrib-debuginfo", rpm: "postgresql10-contrib-debuginfo~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-debuginfo", rpm: "postgresql10-debuginfo~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-debugsource", rpm: "postgresql10-debugsource~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-devel", rpm: "postgresql10-devel~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-devel-debuginfo", rpm: "postgresql10-devel-debuginfo~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plperl", rpm: "postgresql10-plperl~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plperl-debuginfo", rpm: "postgresql10-plperl-debuginfo~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plpython", rpm: "postgresql10-plpython~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-plpython-debuginfo", rpm: "postgresql10-plpython-debuginfo~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-pltcl", rpm: "postgresql10-pltcl~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-pltcl-debuginfo", rpm: "postgresql10-pltcl-debuginfo~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-server", rpm: "postgresql10-server~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-server-debuginfo", rpm: "postgresql10-server-debuginfo~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-test", rpm: "postgresql10-test~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql10-docs", rpm: "postgresql10-docs~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-32bit", rpm: "libecpg6-32bit~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-32bit-debuginfo", rpm: "libecpg6-32bit-debuginfo~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit", rpm: "libpq5-32bit~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit-debuginfo", rpm: "libpq5-32bit-debuginfo~10.9~lp150.3.10.1", rls: "openSUSELeap15.0" ) )){
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
