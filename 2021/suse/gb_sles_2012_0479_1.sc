if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0479.1" );
	script_cve_id( "CVE-2006-7250", "CVE-2012-0884", "CVE-2012-1165" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-06 02:29:00 +0000 (Sat, 06 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0479-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1|SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0479-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120479-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'OpenSSL' package(s) announced via the SUSE-SU-2012:0479-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following security issues have been fixed:

 *

 Specially crafted MIME headers could cause openssl's ans1 parser to dereference a NULL pointer leading to a Denial of Service (CVE-2006-7250) or fail verfication
(CVE-2012-1165).

 *

 The implementation of Cryptographic Message Syntax
(CMS) and PKCS #7 in OpenSSL was vulnerable to a Million Message Attack (MMA) adaptive chosen ciphertext attack
(CVE-2012-0884).

Additionally, the following issues have been fixed:

 * bnc#749213 - Free headers after use in error message
 * bnc#749210 - Symmetric crypto errors in PKCS7_decrypt
 * bnc#749735 - Memory leak when creating public keys

Security Issue references:

 * CVE-2006-7250
>
 * CVE-2012-1165
>
 * CVE-2012-0884
>" );
	script_tag( name: "affected", value: "'OpenSSL' package(s) on SUSE Linux Enterprise Desktop 11 SP1, SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP1, SUSE Linux Enterprise Software Development Kit 11 SP2." );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8", rpm: "libopenssl0_9_8~0.9.8j~0.32.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-32bit", rpm: "libopenssl0_9_8-32bit~0.9.8j~0.32.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-x86", rpm: "libopenssl0_9_8-x86~0.9.8j~0.32.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8j~0.32.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~0.9.8j~0.32.1", rls: "SLES11.0SP1" ) )){
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8", rpm: "libopenssl0_9_8~0.9.8j~0.32.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-32bit", rpm: "libopenssl0_9_8-32bit~0.9.8j~0.32.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-x86", rpm: "libopenssl0_9_8-x86~0.9.8j~0.32.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8j~0.32.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~0.9.8j~0.32.1", rls: "SLES11.0SP2" ) )){
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

