if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1181.2" );
	script_cve_id( "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-4000" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-15 02:29:00 +0000 (Wed, 15 Nov 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1181-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1181-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151181-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'OpenSSL' package(s) announced via the SUSE-SU-2015:1181-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL was updated to fix several security issues.
CVE-2015-4000: The Logjam Attack ( weakdh.org ) has been addressed by rejecting connections with DH parameters shorter than 1024 bits.
We now also generate 2048-bit DH parameters by default.
CVE-2015-1788: Malformed ECParameters could cause an infinite loop.
CVE-2015-1789: An out-of-bounds read in X509_cmp_time was fixed.
CVE-2015-1790: A PKCS7 decoder crash with missing EnvelopedContent was fixed.
fixed a timing side channel in RSA decryption (bnc#929678)
Additional changes:
In the default SSL cipher string EXPORT ciphers are now disabled. This will only get active if applications get rebuilt and actually use this string. (bnc#931698)
Security Issues:
CVE-2015-1788 CVE-2015-1789 CVE-2015-1790 CVE-2015-4000" );
	script_tag( name: "affected", value: "'OpenSSL' package(s) on SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8a~18.92.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-32bit", rpm: "openssl-32bit~0.9.8a~18.92.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~0.9.8a~18.92.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-devel-32bit", rpm: "openssl-devel-32bit~0.9.8a~18.92.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~0.9.8a~18.92.1", rls: "SLES10.0SP4" ) )){
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

