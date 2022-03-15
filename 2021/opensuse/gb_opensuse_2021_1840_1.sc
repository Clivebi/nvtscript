if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853950" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2021-21341", "CVE-2021-21342", "CVE-2021-21343", "CVE-2021-21344", "CVE-2021-21345", "CVE-2021-21346", "CVE-2021-21347", "CVE-2021-21348", "CVE-2021-21349", "CVE-2021-21350", "CVE-2021-21351" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:04:59 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for xstream (openSUSE-SU-2021:1840-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1840-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/APETSNTGJFG76V7J5X4K4LWA77F5743O" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xstream'
  package(s) announced via the openSUSE-SU-2021:1840-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xstream fixes the following issues:

  - Upgrade to 1.4.16

  - CVE-2021-21351: remote attacker to load and execute arbitrary code
       (bsc#1184796)

  - CVE-2021-21349: SSRF can lead to a remote attacker to request data from
       internal resources (bsc#1184797)

  - CVE-2021-21350: arbitrary code execution (bsc#1184380)

  - CVE-2021-21348: remote attacker could cause denial of service by
       consuming maximum CPU time (bsc#1184374)

  - CVE-2021-21347: remote attacker to load and execute arbitrary code from
       a remote host (bsc#1184378)

  - CVE-2021-21344: remote attacker could load and execute arbitrary code
       from a remote host (bsc#1184375)

  - CVE-2021-21342: server-side forgery (bsc#1184379)

  - CVE-2021-21341: remote attacker could cause a denial of service by
       allocating 100% CPU time (bsc#1184377)

  - CVE-2021-21346: remote attacker could load and execute arbitrary code
       (bsc#1184373)

  - CVE-2021-21345: remote attacker with sufficient rights could execute
       commands (bsc#1184372)

  - CVE-2021-21343: replace or inject objects, that result in the deletion
       of files on the local host (bsc#1184376)" );
	script_tag( name: "affected", value: "'xstream' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "xstream", rpm: "xstream~1.4.16~3.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xstream-benchmark", rpm: "xstream-benchmark~1.4.16~3.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xstream-javadoc", rpm: "xstream-javadoc~1.4.16~3.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xstream-parent", rpm: "xstream-parent~1.4.16~3.8.1", rls: "openSUSELeap15.3" ) )){
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

