if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.1267.1" );
	script_cve_id( "CVE-2016-0702", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2108", "CVE-2016-2109" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:1267-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:1267-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20161267-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'compat-openssl098' package(s) announced via the SUSE-SU-2016:1267-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for compat-openssl098 fixes the following issues:
- CVE-2016-2108: Memory corruption in the ASN.1 encoder (bsc#977617)
- CVE-2016-2105: EVP_EncodeUpdate overflow (bsc#977614)
- CVE-2016-2106: EVP_EncryptUpdate overflow (bsc#977615)
- CVE-2016-2109: ASN.1 BIO excessive memory allocation (bsc#976942)
- CVE-2016-0702: Side channel attack on modular exponentiation
 'CacheBleed' (bsc#968050)
- bsc#976943: Buffer overrun in ASN1_parse The following non-security bugs were fixed:
- bsc#889013: Rename README.SuSE to the new spelling (bsc#889013)" );
	script_tag( name: "affected", value: "'compat-openssl098' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Module for Legacy Software 12, SUSE Linux Enterprise Server for SAP 12-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "compat-openssl098-debugsource", rpm: "compat-openssl098-debugsource~0.9.8j~97.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8", rpm: "libopenssl0_9_8~0.9.8j~97.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-32bit", rpm: "libopenssl0_9_8-32bit~0.9.8j~97.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-debuginfo", rpm: "libopenssl0_9_8-debuginfo~0.9.8j~97.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-debuginfo-32bit", rpm: "libopenssl0_9_8-debuginfo-32bit~0.9.8j~97.1", rls: "SLES12.0" ) )){
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

