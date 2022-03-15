if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.2655.1" );
	script_cve_id( "CVE-2017-14621" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:52 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-28 15:22:00 +0000 (Thu, 28 Sep 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:2655-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:2655-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20172655-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'portus' package(s) announced via the SUSE-SU-2017:2655-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for portus fixes the following issues:
- CVE-2017-14621: Fixed a XSS attack via the Team field, related to
 typeahead. (bsc#1059664)" );
	script_tag( name: "affected", value: "'portus' package(s) on SUSE Linux Enterprise Module for Containers 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "portus", rpm: "portus~2.2.0~20.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "portus-debuginfo", rpm: "portus-debuginfo~2.2.0~20.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "portus-debugsource", rpm: "portus-debugsource~2.2.0~20.3.1", rls: "SLES12.0" ) )){
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

