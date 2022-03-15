if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2017.1203" );
	script_cve_id( "CVE-2016-7444", "CVE-2017-5334", "CVE-2017-5335", "CVE-2017-5336", "CVE-2017-5337", "CVE-2017-7507" );
	script_tag( name: "creation_date", value: "2020-01-23 10:58:16 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for gnutls (EulerOS-SA-2017-1203)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2017-1203" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1203" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'gnutls' package(s) announced via the EulerOS-SA-2017-1203 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A double-free flaw was found in the way GnuTLS parsed certain X.509 certificates with Proxy Certificate Information extension. An attacker could create a specially-crafted certificate which, when processed by an application compiled against GnuTLS, could cause that application to crash. (CVE-2017-5334)

Multiple flaws were found in the way gnutls processed OpenPGP certificates. An attacker could create specially crafted OpenPGP certificates which, when parsed by gnutls, would cause it to crash. (CVE-2017-5335, CVE-2017-5336, CVE-2017-5337, CVE-2017-7869)

A null pointer dereference flaw was found in the way GnuTLS processed ClientHello messages with status_request extension. A remote attacker could use this flaw to cause an application compiled with GnuTLS to crash. (CVE-2017-7507)

A flaw was found in the way GnuTLS validated certificates using OCSP responses. This could falsely report a certificate as valid under certain circumstances. (CVE-2016-7444)" );
	script_tag( name: "affected", value: "'gnutls' package(s) on Huawei EulerOS V2.0SP1." );
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
if(release == "EULEROS-2.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~3.3.26~9", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-c++", rpm: "gnutls-c++~3.3.26~9", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-dane", rpm: "gnutls-dane~3.3.26~9", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-devel", rpm: "gnutls-devel~3.3.26~9", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-utils", rpm: "gnutls-utils~3.3.26~9", rls: "EULEROS-2.0SP1" ) )){
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

