if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.14667.1" );
	script_cve_id( "CVE-2021-23840", "CVE-2021-23841" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:41 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:14667-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:14667-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-202114667-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl1' package(s) announced via the SUSE-SU-2021:14667-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssl1 fixes the following issues:

CVE-2021-23840: Fixed an Integer overflow in CipherUpdate (bsc#1182333)

CVE-2021-23841: Fixed a Null pointer dereference in
 X509_issuer_and_serial_hash() (bsc#1182331)" );
	script_tag( name: "affected", value: "'openssl1' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Server 11." );
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
if(release == "SLES11.0"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1-devel", rpm: "libopenssl1-devel~1.0.1g~0.58.33.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0", rpm: "libopenssl1_0_0~1.0.1g~0.58.33.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-32bit", rpm: "libopenssl1_0_0-32bit~1.0.1g~0.58.33.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-x86", rpm: "libopenssl1_0_0-x86~1.0.1g~0.58.33.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl1", rpm: "openssl1~1.0.1g~0.58.33.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl1-doc", rpm: "openssl1-doc~1.0.1g~0.58.33.1", rls: "SLES11.0" ) )){
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

