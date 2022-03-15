if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851612" );
	script_version( "2021-09-15T14:07:14+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 14:07:14 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-09 07:20:32 +0200 (Sat, 09 Sep 2017)" );
	script_cve_id( "CVE-2017-7546", "CVE-2017-7547", "CVE-2017-7548" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for postgresql96 (openSUSE-SU-2017:2391-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql96'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql96 fixes the following issues:

  * CVE-2017-7547: Further restrict visibility of
  pg_user_mappings.umoptions, to protect passwords stored as user mapping
  options. (bsc#1051685)

  * CVE-2017-7546: Disallow empty passwords in all password-based
  authentication methods. (bsc#1051684)

  * CVE-2017-7548: lo_put() function ignores ACLs. (bsc#1053259)

  This update was imported from the SUSE:SLE-12:Update update project." );
	script_tag( name: "affected", value: "postgresql96 on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:2391-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo", rpm: "libecpg6-debuginfo~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo", rpm: "libpq5-debuginfo~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96", rpm: "postgresql96~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib", rpm: "postgresql96-contrib~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib-debuginfo", rpm: "postgresql96-contrib-debuginfo~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debuginfo", rpm: "postgresql96-debuginfo~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debugsource", rpm: "postgresql96-debugsource~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-devel", rpm: "postgresql96-devel~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-devel-debuginfo", rpm: "postgresql96-devel-debuginfo~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-libs-debugsource", rpm: "postgresql96-libs-debugsource~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plperl", rpm: "postgresql96-plperl~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plperl-debuginfo", rpm: "postgresql96-plperl-debuginfo~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plpython", rpm: "postgresql96-plpython~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plpython-debuginfo", rpm: "postgresql96-plpython-debuginfo~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-pltcl", rpm: "postgresql96-pltcl~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-pltcl-debuginfo", rpm: "postgresql96-pltcl-debuginfo~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server", rpm: "postgresql96-server~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server-debuginfo", rpm: "postgresql96-server-debuginfo~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-test", rpm: "postgresql96-test~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-32bit", rpm: "libecpg6-32bit~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo-32bit", rpm: "libecpg6-debuginfo-32bit~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit", rpm: "libpq5-32bit~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo-32bit", rpm: "libpq5-debuginfo-32bit~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-docs", rpm: "postgresql96-docs~9.6.4~5.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo", rpm: "libecpg6-debuginfo~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo", rpm: "libpq5-debuginfo~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96", rpm: "postgresql96~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib", rpm: "postgresql96-contrib~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib-debuginfo", rpm: "postgresql96-contrib-debuginfo~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debuginfo", rpm: "postgresql96-debuginfo~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debugsource", rpm: "postgresql96-debugsource~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-devel", rpm: "postgresql96-devel~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-devel-debuginfo", rpm: "postgresql96-devel-debuginfo~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-libs-debugsource", rpm: "postgresql96-libs-debugsource~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plperl", rpm: "postgresql96-plperl~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plperl-debuginfo", rpm: "postgresql96-plperl-debuginfo~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plpython", rpm: "postgresql96-plpython~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-plpython-debuginfo", rpm: "postgresql96-plpython-debuginfo~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-pltcl", rpm: "postgresql96-pltcl~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-pltcl-debuginfo", rpm: "postgresql96-pltcl-debuginfo~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server", rpm: "postgresql96-server~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server-debuginfo", rpm: "postgresql96-server-debuginfo~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-test", rpm: "postgresql96-test~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-docs", rpm: "postgresql96-docs~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-32bit", rpm: "libecpg6-32bit~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo-32bit", rpm: "libecpg6-debuginfo-32bit~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit", rpm: "libpq5-32bit~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo-32bit", rpm: "libpq5-debuginfo-32bit~9.6.4~6.1", rls: "openSUSELeap42.3" ) )){
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

