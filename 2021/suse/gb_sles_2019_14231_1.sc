if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.14231.1" );
	script_cve_id( "CVE-2019-12625", "CVE-2019-12900" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:13 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-09-19T02:20:11+0000" );
	script_tag( name: "last_modification", value: "2021-09-19 02:20:11 +0000 (Sun, 19 Sep 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-14 12:18:00 +0000 (Tue, 14 Sep 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:14231-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:14231-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-201914231-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2019:14231-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for clamav fixes the following issues:

Security issues fixed:
CVE-2019-12625: Fixed a ZIP bomb issue by adding detection and
 heuristics for zips with overlapping files (bsc#1144504).

CVE-2019-12900: Fixed an out-of-bounds write in decompress.c with many
 selectors (bsc#1149458).

Non-security issue fixed:
Added the --max-scantime clamscan option and MaxScanTime clamd
 configuration option." );
	script_tag( name: "affected", value: "'clamav' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.100.3~0.20.26.1", rls: "SLES11.0SP4" ) )){
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

