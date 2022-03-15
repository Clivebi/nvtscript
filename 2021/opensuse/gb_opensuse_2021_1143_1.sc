if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854061" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2019-14275", "CVE-2019-19555", "CVE-2019-19746", "CVE-2019-19797", "CVE-2021-3561" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-07 03:15:00 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 03:02:58 +0000 (Wed, 11 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for transfig (openSUSE-SU-2021:1143-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1143-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LKD7IBCZKGMDHLZ7H4T5P7WTXHNFSOB6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'transfig'
  package(s) announced via the openSUSE-SU-2021:1143-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for transfig fixes the following issues:

     Update to version 3.2.8, including fixes for

  - CVE-2021-3561: overflow in fig2dev/read.c in function read_colordef()
       (bsc#1186329).

  - CVE-2019-19797: out-of-bounds write in read_colordef in read.c
       (bsc#1159293).

  - CVE-2019-19555: stack-based buffer overflow because of an incorrect
       sscanf (bsc#1161698).

  - CVE-2019-19746: segmentation fault and out-of-bounds write because of an
       integer overflow via a large arrow type (bsc#1159130).

  - CVE-2019-14275: stack-based buffer overflow in the calc_arrow function
       in bound.c (bsc#1143650).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'transfig' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "transfig", rpm: "transfig~3.2.8a~lp152.6.6.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "transfig-debuginfo", rpm: "transfig-debuginfo~3.2.8a~lp152.6.6.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "transfig-debugsource", rpm: "transfig-debugsource~3.2.8a~lp152.6.6.2", rls: "openSUSELeap15.2" ) )){
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

