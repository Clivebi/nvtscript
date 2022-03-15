if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2270" );
	script_cve_id( "CVE-2020-13645" );
	script_tag( name: "creation_date", value: "2021-08-09 10:11:13 +0000 (Mon, 09 Aug 2021)" );
	script_version( "2021-08-09T11:38:50+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 11:38:50 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-22 14:47:00 +0000 (Tue, 22 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for glib-networking (EulerOS-SA-2021-2270)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP9" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2270" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2270" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'glib-networking' package(s) announced via the EulerOS-SA-2021-2270 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In GNOME glib-networking through 2.64.2, the implementation of GTlsClientConnection skips hostname verification of the server's TLS certificate if the application fails to specify the expected server identity. This is in contrast to its intended documented behavior, to fail the certificate verification. Applications that fail to provide the server identity, including Balsa before 2.5.11 and 2.6.x before 2.6.1, accept a TLS certificate if the certificate is valid for any host.(CVE-2020-13645)" );
	script_tag( name: "affected", value: "'glib-networking' package(s) on Huawei EulerOS V2.0SP9." );
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
if(release == "EULEROS-2.0SP9"){
	if(!isnull( res = isrpmvuln( pkg: "glib-networking", rpm: "glib-networking~2.58.0~7.h1.eulerosv2r9", rls: "EULEROS-2.0SP9" ) )){
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

