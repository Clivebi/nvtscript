if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2196" );
	script_cve_id( "CVE-2019-17362" );
	script_tag( name: "creation_date", value: "2021-07-13 12:59:17 +0000 (Tue, 13 Jul 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-09 19:15:00 +0000 (Sat, 09 Nov 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for libtomcrypt (EulerOS-SA-2021-2196)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.9\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2196" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2196" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libtomcrypt' package(s) announced via the EulerOS-SA-2021-2196 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In LibTomCrypt through 1.18.2, the der_decode_utf8_string function (in der_decode_utf8_string.c) does not properly detect certain invalid UTF-8 sequences. This allows context-dependent attackers to cause a denial of service (out-of-bounds read and crash) or read information from other memory locations via carefully crafted DER-encoded data.(CVE-2019-17362)" );
	script_tag( name: "affected", value: "'libtomcrypt' package(s) on Huawei EulerOS Virtualization release 2.9.0." );
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
if(release == "EULEROSVIRT-2.9.0"){
	if(!isnull( res = isrpmvuln( pkg: "libtomcrypt", rpm: "libtomcrypt~1.18.2~3.h1.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
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

