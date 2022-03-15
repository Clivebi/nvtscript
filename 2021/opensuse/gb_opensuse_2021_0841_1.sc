if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853850" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2021-32625" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 16:48:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-06 03:01:47 +0000 (Sun, 06 Jun 2021)" );
	script_name( "openSUSE: Security Advisory for redis (openSUSE-SU-2021:0841-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0841-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/B74HW6HBAH5TAP4L5LLUY3KI4JBTVQS3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'redis'
  package(s) announced via the openSUSE-SU-2021:0841-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for redis fixes the following issues:

     redis was updated to 6.0.14:

  * CVE-2021-32625: An integer overflow bug could be exploited by using the
       STRALGO LCS command to cause remote remote code execution (boo#1186722)

  * Fix crash in UNLINK on a stream key with deleted consumer groups

  * SINTERSTORE: Add missing keyspace del event when none of the sources
       exist" );
	script_tag( name: "affected", value: "'redis' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "redis", rpm: "redis~6.0.14~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "redis-debuginfo", rpm: "redis-debuginfo~6.0.14~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "redis-debugsource", rpm: "redis-debugsource~6.0.14~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
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

