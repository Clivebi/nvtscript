if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853624" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2020-12658" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-08 13:46:00 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:57:15 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for gssproxy (openSUSE-SU-2021:0531-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0531-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/I6NDFFQCNMQW6SZXPZI34VPX7QS37NS5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gssproxy'
  package(s) announced via the openSUSE-SU-2021:0531-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gssproxy fixes the following issues:

  - CVE-2020-12658: Fixed an issue where gssproxy was not unlocking
       cond_mutex before pthread exit in gp_worker_main() (bsc#1180515).

     This update was imported from the SUSE:SLE-15-SP1:Update update project." );
	script_tag( name: "affected", value: "'gssproxy' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "gssproxy", rpm: "gssproxy~0.8.2~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gssproxy-debuginfo", rpm: "gssproxy-debuginfo~0.8.2~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gssproxy-debugsource", rpm: "gssproxy-debugsource~0.8.2~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

