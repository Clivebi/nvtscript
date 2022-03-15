if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0475.1" );
	script_cve_id( "CVE-2014-0106" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-16 02:29:00 +0000 (Sat, 16 Dec 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0475-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0475-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140475-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sudo' package(s) announced via the SUSE-SU-2014:0475-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This collective update for sudo provides fixes for the following issues:

 * Security policy bypass when env_reset is disabled.
(CVE-2014-0106, bnc#866503)
 * Regression in the previous update that causes a segmentation fault when running 'sudo -s'. (bnc#868444)
 * Command 'who -m' prints no output when using log_input/log_output sudo options. (bnc#863025)

Security Issues references:

 * CVE-2014-0106
>" );
	script_tag( name: "affected", value: "'sudo' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "sudo", rpm: "sudo~1.7.6p2~0.21.1", rls: "SLES11.0SP3" ) )){
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

