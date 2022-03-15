if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1910" );
	script_cve_id( "CVE-2020-25715", "CVE-2021-20179" );
	script_tag( name: "creation_date", value: "2021-05-19 06:22:33 +0000 (Wed, 19 May 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-24 01:58:00 +0000 (Wed, 24 Mar 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for pki-core (EulerOS-SA-2021-1910)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1910" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1910" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'pki-core' package(s) announced via the EulerOS-SA-2021-1910 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in pki-core. A specially crafted POST request can be used to reflect a DOM-based cross-site scripting (XSS) attack to inject code into the search query form which can get automatically executed. The highest threat from this vulnerability is to data integrity.(CVE-2020-25715)

A flaw was found in pki-core. An attacker who has successfully compromised a key could use this flaw to renew the corresponding certificate over and over again, as long as it is not explicitly revoked. The highest threat from this vulnerability is to data confidentiality and integrity.(CVE-2021-20179)" );
	script_tag( name: "affected", value: "'pki-core' package(s) on Huawei EulerOS V2.0SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "pki-base", rpm: "pki-base~10.5.1~14.h6.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pki-base-java", rpm: "pki-base-java~10.5.1~14.h6.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pki-ca", rpm: "pki-ca~10.5.1~14.h6.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pki-kra", rpm: "pki-kra~10.5.1~14.h6.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pki-server", rpm: "pki-server~10.5.1~14.h6.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pki-symkey", rpm: "pki-symkey~10.5.1~14.h6.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pki-tools", rpm: "pki-tools~10.5.1~14.h6.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

