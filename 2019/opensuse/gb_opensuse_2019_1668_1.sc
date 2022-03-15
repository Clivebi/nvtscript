if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852603" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-10130" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 14:08:00 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-07-01 02:00:40 +0000 (Mon, 01 Jul 2019)" );
	script_name( "openSUSE: Security Advisory for postgresql96 (openSUSE-SU-2019:1668-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1668-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00088.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql96'
  package(s) announced via the openSUSE-SU-2019:1668-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql96 fixes the following issues:

  Security issue fixed:

  - CVE-2019-10130: Prevent row-level security policies from being bypassed
  via selectivity estimators (bsc#1134689).

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1668=1" );
	script_tag( name: "affected", value: "'postgresql96' package(s) on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "postgresql96", rpm: "postgresql96~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib", rpm: "postgresql96-contrib~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib-debuginfo", rpm: "postgresql96-contrib-debuginfo~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debuginfo", rpm: "postgresql96-debuginfo~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debugsource", rpm: "postgresql96-debugsource~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-devel", rpm: "postgresql96-devel~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-devel-debuginfo", rpm: "postgresql96-devel-debuginfo~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-libs-debugsource", rpm: "postgresql96-libs-debugsource~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plperl", rpm: "postgresql96-plperl~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plperl-debuginfo", rpm: "postgresql96-plperl-debuginfo~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plpython", rpm: "postgresql96-plpython~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plpython-debuginfo", rpm: "postgresql96-plpython-debuginfo~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-pltcl", rpm: "postgresql96-pltcl~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-pltcl-debuginfo", rpm: "postgresql96-pltcl-debuginfo~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server", rpm: "postgresql96-server~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server-debuginfo", rpm: "postgresql96-server-debuginfo~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-test", rpm: "postgresql96-test~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-docs", rpm: "postgresql96-docs~9.6.13~24.1", rls: "openSUSELeap42.3" ) )){
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

