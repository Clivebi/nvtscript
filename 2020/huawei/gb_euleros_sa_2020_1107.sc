if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1107" );
	script_cve_id( "CVE-2019-14867" );
	script_tag( name: "creation_date", value: "2020-02-24 09:05:07 +0000 (Mon, 24 Feb 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-05 00:15:00 +0000 (Wed, 05 Feb 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for ipa (EulerOS-SA-2020-1107)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1107" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1107" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ipa' package(s) announced via the EulerOS-SA-2020-1107 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in IPA, all 4.6.x versions before 4.6.7, all 4.7.x versions before 4.7.4 and all 4.8.x versions before 4.8.3, in the way the internal function ber_scanf() was used in some components of the IPA server, which parsed kerberos key data. An unauthenticated attacker who could trigger parsing of the krb principal key could cause the IPA server to crash or in some conditions, cause arbitrary code to be executed on the server hosting the IPA server.(CVE-2019-14867)" );
	script_tag( name: "affected", value: "'ipa' package(s) on Huawei EulerOS V2.0SP5." );
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
if(release == "EULEROS-2.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "ipa-client", rpm: "ipa-client~4.5.4~10.3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ipa-client-common", rpm: "ipa-client-common~4.5.4~10.3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ipa-common", rpm: "ipa-common~4.5.4~10.3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ipa-python-compat", rpm: "ipa-python-compat~4.5.4~10.3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ipa-server", rpm: "ipa-server~4.5.4~10.3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ipa-server-common", rpm: "ipa-server-common~4.5.4~10.3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ipa-server-dns", rpm: "ipa-server-dns~4.5.4~10.3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ipa-server-trust-ad", rpm: "ipa-server-trust-ad~4.5.4~10.3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-ipaclient", rpm: "python2-ipaclient~4.5.4~10.3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-ipalib", rpm: "python2-ipalib~4.5.4~10.3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-ipaserver", rpm: "python2-ipaserver~4.5.4~10.3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

