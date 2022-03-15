if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3290.1" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:35 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-06-09 15:01:40 +0000 (Wed, 09 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3290-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3290-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183290-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pam_pkcs11' package(s) announced via the SUSE-SU-2018:3290-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for pam_pkcs11 fixes the following security issues:
It was possible to replay an authentication by using a specially
 prepared smartcard or token (bsc#1105012)

Prevent buffer overflow if a user has a home directory with a length of
 more than 512 bytes (bsc#1105012)

Memory not cleaned properly before free() (bsc#1105012)

This non-security issue was fixed:
Fix segfault and fetch problems when checking CRLs" );
	script_tag( name: "affected", value: "'pam_pkcs11' package(s) on SUSE Linux Enterprise Module for Basesystem 15." );
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
	if(!isnull( res = isrpmvuln( pkg: "pam_pkcs11", rpm: "pam_pkcs11~0.6.9~3.3.3", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_pkcs11-32bit", rpm: "pam_pkcs11-32bit~0.6.9~3.3.3", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_pkcs11-32bit-debuginfo", rpm: "pam_pkcs11-32bit-debuginfo~0.6.9~3.3.3", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_pkcs11-debuginfo", rpm: "pam_pkcs11-debuginfo~0.6.9~3.3.3", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_pkcs11-debugsource", rpm: "pam_pkcs11-debugsource~0.6.9~3.3.3", rls: "SLES15.0" ) )){
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

