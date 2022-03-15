if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.2109.1" );
	script_cve_id( "CVE-2020-14019" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:58 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-07 12:15:00 +0000 (Fri, 07 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:2109-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:2109-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20202109-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-rtslib-fb' package(s) announced via the SUSE-SU-2020:2109-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-rtslib-fb fixes the following issues:

Update to version v2.1.73 (bsc#1173257 CVE-2020-14019):
 * version 2.1.73
 * save_to_file: fix fd open mode
 * saveconfig: copy temp configfile with permissions
 * saveconfig: open the temp configfile with modes set
 * Fix 'is not' with a literal SyntaxWarning
 * Fix an incorrect config path in two comments
 * version 2.1.72
 * Do not change dbroot after drivers have been registered
 * Remove '_if_needed' from RTSRoot._set_dbroot()'s name Replacing old
 tarball with python-rtslib-fb-v2.1.73.tar.xz" );
	script_tag( name: "affected", value: "'python-rtslib-fb' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Python2 15-SP2." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "python3-rtslib-fb", rpm: "python3-rtslib-fb~2.1.73~3.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-rtslib-fb", rpm: "python2-rtslib-fb~2.1.73~3.3.1", rls: "SLES15.0SP2" ) )){
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

