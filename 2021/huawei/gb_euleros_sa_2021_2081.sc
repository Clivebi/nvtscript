if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2081" );
	script_cve_id( "CVE-2019-19906" );
	script_tag( name: "creation_date", value: "2021-07-07 08:40:26 +0000 (Wed, 07 Jul 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for cyrus-sasl (EulerOS-SA-2021-2081)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.2\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2081" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2081" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'cyrus-sasl' package(s) announced via the EulerOS-SA-2021-2081 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "cyrus-sasl (aka Cyrus SASL) 2.1.27 has an out-of-bounds write leading to unauthenticated remote denial-of-service in OpenLDAP via a malformed LDAP packet. The OpenLDAP crash is ultimately caused by an off-by-one error in _sasl_add_string in common.c in cyrus-sasl.(CVE-2019-19906)" );
	script_tag( name: "affected", value: "'cyrus-sasl' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0." );
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
if(release == "EULEROSVIRTARM64-3.0.2.0"){
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl", rpm: "cyrus-sasl~2.1.26~23.h3", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi", rpm: "cyrus-sasl-gssapi~2.1.26~23.h3", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-lib", rpm: "cyrus-sasl-lib~2.1.26~23.h3", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-md5", rpm: "cyrus-sasl-md5~2.1.26~23.h3", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain", rpm: "cyrus-sasl-plain~2.1.26~23.h3", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
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

