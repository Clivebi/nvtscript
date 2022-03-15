if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853786" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2021-25317" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-27 16:37:00 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-01 03:02:11 +0000 (Sat, 01 May 2021)" );
	script_name( "openSUSE: Security Advisory for cups (openSUSE-SU-2021:0638-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0638-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7GKB5OH3W4MLNXHW3ZQK7GEVLAEMXZ7C" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cups'
  package(s) announced via the openSUSE-SU-2021:0638-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for cups fixes the following issues:

  - CVE-2021-25317: ownership of /var/log/cups could allow privilege
       escalation from lp user to root via symlink attacks (bsc#1184161)

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'cups' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "cups", rpm: "cups~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-client", rpm: "cups-client~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-client-debuginfo", rpm: "cups-client-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-config", rpm: "cups-config~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-ddk", rpm: "cups-ddk~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-ddk-debuginfo", rpm: "cups-ddk-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-debuginfo", rpm: "cups-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-debugsource", rpm: "cups-debugsource~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-devel", rpm: "cups-devel~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcups2", rpm: "libcups2~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcups2-debuginfo", rpm: "libcups2-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupscgi1", rpm: "libcupscgi1~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupscgi1-debuginfo", rpm: "libcupscgi1-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsimage2", rpm: "libcupsimage2~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsimage2-debuginfo", rpm: "libcupsimage2-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsmime1", rpm: "libcupsmime1~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsmime1-debuginfo", rpm: "libcupsmime1-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsppdc1", rpm: "libcupsppdc1~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsppdc1-debuginfo", rpm: "libcupsppdc1-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-devel-32bit", rpm: "cups-devel-32bit~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcups2-32bit", rpm: "libcups2-32bit~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcups2-32bit-debuginfo", rpm: "libcups2-32bit-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupscgi1-32bit", rpm: "libcupscgi1-32bit~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupscgi1-32bit-debuginfo", rpm: "libcupscgi1-32bit-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsimage2-32bit", rpm: "libcupsimage2-32bit~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsimage2-32bit-debuginfo", rpm: "libcupsimage2-32bit-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsmime1-32bit", rpm: "libcupsmime1-32bit~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsmime1-32bit-debuginfo", rpm: "libcupsmime1-32bit-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsppdc1-32bit", rpm: "libcupsppdc1-32bit~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcupsppdc1-32bit-debuginfo", rpm: "libcupsppdc1-32bit-debuginfo~2.2.7~lp152.9.9.1", rls: "openSUSELeap15.2" ) )){
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

