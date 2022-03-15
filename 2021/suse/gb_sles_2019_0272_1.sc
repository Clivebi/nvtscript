if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0272.1" );
	script_cve_id( "CVE-2018-14404", "CVE-2018-16468", "CVE-2018-16470" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:31 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-10 01:15:00 +0000 (Thu, 10 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0272-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0272-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190272-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rmt-server' package(s) announced via the SUSE-SU-2019:0272-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rmt-server to version 1.1.1 fixes the following issues:

The following issues have been fixed:
Fixed migration problems which caused some extensions / modules to be
 dropped (bsc#1118584, bsc#1118579)

Fixed listing of mirrored products (bsc#1102193)

Include online migration paths into offline migration (bsc#1117106)

Sync products that do not have a base product (bsc#1109307)

Fixed SLP auto discovery for RMT (bsc#1113760)

Update dependencies for security fixes:
CVE-2018-16468: Update loofah to 2.2.3 (bsc#1113969)

CVE-2018-16470: Update rack to 2.0.6 (bsc#1114831)

CVE-2018-14404: Update nokogiri to 1.8.5 (bsc#1102046)" );
	script_tag( name: "affected", value: "'rmt-server' package(s) on SUSE Linux Enterprise Module for Server Applications 15." );
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
	if(!isnull( res = isrpmvuln( pkg: "rmt-server", rpm: "rmt-server~1.1.1~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rmt-server-debuginfo", rpm: "rmt-server-debuginfo~1.1.1~3.13.1", rls: "SLES15.0" ) )){
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

