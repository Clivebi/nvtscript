if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2068.1" );
	script_cve_id( "CVE-2018-1417", "CVE-2018-2783", "CVE-2018-2790", "CVE-2018-2794", "CVE-2018-2795", "CVE-2018-2796", "CVE-2018-2797", "CVE-2018-2798", "CVE-2018-2799", "CVE-2018-2800", "CVE-2018-2814", "CVE-2018-2825", "CVE-2018-2826" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:42 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2068-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2068-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182068-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2018:2068-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "IBM Java was updated to version 8.0.5.15 [bsc#1093311, bsc#1085449]
Security fixes:
- CVE-2018-2826 CVE-2018-2825 CVE-2018-2814 CVE-2018-2794 CVE-2018-2783
 CVE-2018-2799 CVE-2018-2798 CVE-2018-2797 CVE-2018-2796 CVE-2018-2795
 CVE-2018-2800 CVE-2018-2790 CVE-2018-1417
- Removed translations in the java-1_8_0-ibm-devel-32bit package as they
 conflict with those in java-1_8_0-ibm-devel." );
	script_tag( name: "affected", value: "'java-1_8_0-ibm' package(s) on SUSE Linux Enterprise Module for Legacy Software 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm", rpm: "java-1_8_0-ibm~1.8.0_sr5.15~3.3.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-alsa", rpm: "java-1_8_0-ibm-alsa~1.8.0_sr5.15~3.3.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-devel", rpm: "java-1_8_0-ibm-devel~1.8.0_sr5.15~3.3.4", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-plugin", rpm: "java-1_8_0-ibm-plugin~1.8.0_sr5.15~3.3.4", rls: "SLES15.0" ) )){
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

