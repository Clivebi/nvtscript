if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.3019.1" );
	script_cve_id( "CVE-2021-3712" );
	script_tag( name: "creation_date", value: "2021-09-23 07:04:43 +0000 (Thu, 23 Sep 2021)" );
	script_version( "2021-09-23T07:04:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-23 07:04:43 +0000 (Thu, 23 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-31 16:48:00 +0000 (Tue, 31 Aug 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:3019-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:3019-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20213019-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'compat-openssl098' package(s) announced via the SUSE-SU-2021:3019-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for compat-openssl098 fixes the following issues:

CVE-2021-3712: This is an update for the incomplete fix for
 CVE-2021-3712. Read buffer overruns processing ASN.1 strings
 (bsc#1189521)." );
	script_tag( name: "affected", value: "'compat-openssl098' package(s) on SUSE Linux Enterprise Module for Legacy Software 12, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "compat-openssl098-debugsource", rpm: "compat-openssl098-debugsource~0.9.8j~106.30.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8", rpm: "libopenssl0_9_8~0.9.8j~106.30.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-32bit", rpm: "libopenssl0_9_8-32bit~0.9.8j~106.30.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-debuginfo", rpm: "libopenssl0_9_8-debuginfo~0.9.8j~106.30.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-debuginfo-32bit", rpm: "libopenssl0_9_8-debuginfo-32bit~0.9.8j~106.30.2", rls: "SLES12.0" ) )){
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

