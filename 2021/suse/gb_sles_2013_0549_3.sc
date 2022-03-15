if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.0549.3" );
	script_cve_id( "CVE-2012-4929", "CVE-2013-0166", "CVE-2013-0169" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-09 01:29:00 +0000 (Thu, 09 Aug 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:0549-3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:0549-3" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20130549-3/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'OpenSSL' package(s) announced via the SUSE-SU-2013:0549-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL has been updated to fix several security issues:

 * CVE-2012-4929: Avoid the openssl CRIME attack by disabling SSL compression by default. Setting the environment variable 'OPENSSL_NO_DEFAULT_ZLIB' to 'no'
enables compression again.
 * CVE-2013-0169: Timing attacks against TLS could be used by physically local attackers to gain access to transmitted plain text or private keymaterial. This issue is also known as the 'Lucky-13' issue.
 * CVE-2013-0166: A OCSP invalid key denial of service issue was fixed.

Security Issue references:

 * CVE-2013-0169
>
 * CVE-2013-0166
>" );
	script_tag( name: "affected", value: "'OpenSSL' package(s) on SUSE Linux Enterprise Server 11 SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8", rpm: "libopenssl0_9_8~0.9.8j~0.50.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-32bit", rpm: "libopenssl0_9_8-32bit~0.9.8j~0.50.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-hmac", rpm: "libopenssl0_9_8-hmac~0.9.8j~0.50.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-hmac-32bit", rpm: "libopenssl0_9_8-hmac-32bit~0.9.8j~0.50.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8j~0.50.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~0.9.8j~0.50.1", rls: "SLES11.0SP1" ) )){
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
