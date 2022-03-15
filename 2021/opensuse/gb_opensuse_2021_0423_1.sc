if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853610" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2021-3393" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-04 19:04:00 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:56:49 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for postgresql12 (openSUSE-SU-2021:0423-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0423-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IILVBEHTY5E5NJCJLBHIW7MZUDL25BDR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql12'
  package(s) announced via the openSUSE-SU-2021:0423-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql12 fixes the following issues:

     Upgrade to version 12.6:

  - Reindexing might be needed after applying this update.

  - CVE-2021-3393, bsc#1182040: Fix information leakage in
       constraint-violation error messages.

     This update was imported from the SUSE:SLE-15-SP1:Update update project." );
	script_tag( name: "affected", value: "'postgresql12' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "libecpg6", rpm: "libecpg6~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-debuginfo", rpm: "libecpg6-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5", rpm: "libpq5~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-debuginfo", rpm: "libpq5-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12", rpm: "postgresql12~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-contrib", rpm: "postgresql12-contrib~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-contrib-debuginfo", rpm: "postgresql12-contrib-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-debuginfo", rpm: "postgresql12-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-debugsource", rpm: "postgresql12-debugsource~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-devel", rpm: "postgresql12-devel~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-devel-debuginfo", rpm: "postgresql12-devel-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-llvmjit", rpm: "postgresql12-llvmjit~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-llvmjit-debuginfo", rpm: "postgresql12-llvmjit-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plperl", rpm: "postgresql12-plperl~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plperl-debuginfo", rpm: "postgresql12-plperl-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plpython", rpm: "postgresql12-plpython~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-plpython-debuginfo", rpm: "postgresql12-plpython-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-pltcl", rpm: "postgresql12-pltcl~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-pltcl-debuginfo", rpm: "postgresql12-pltcl-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server", rpm: "postgresql12-server~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server-debuginfo", rpm: "postgresql12-server-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server-devel", rpm: "postgresql12-server-devel~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-server-devel-debuginfo", rpm: "postgresql12-server-devel-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-test", rpm: "postgresql12-test~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql12-docs", rpm: "postgresql12-docs~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-32bit", rpm: "libecpg6-32bit~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libecpg6-32bit-debuginfo", rpm: "libecpg6-32bit-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit", rpm: "libpq5-32bit~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpq5-32bit-debuginfo", rpm: "libpq5-32bit-debuginfo~12.6~lp152.3.16.1", rls: "openSUSELeap15.2" ) )){
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

