if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1424" );
	script_cve_id( "CVE-2015-3218", "CVE-2015-3255", "CVE-2015-4625" );
	script_tag( name: "creation_date", value: "2020-04-16 05:51:24 +0000 (Thu, 16 Apr 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-28 01:29:00 +0000 (Sat, 28 Jul 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for polkit (EulerOS-SA-2020-1424)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1424" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1424" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'polkit' package(s) announced via the EulerOS-SA-2020-1424 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The authentication_agent_new function in polkitbackend/polkitbackendinteractiveauthority.c in PolicyKit (aka polkit) before 0.113 allows local users to cause a denial of service (NULL pointer dereference and polkitd daemon crash) by calling RegisterAuthenticationAgent with an invalid object path.(CVE-2015-3218)



The polkit_backend_action_pool_init function in polkitbackend/polkitbackendactionpool.c in PolicyKit (aka polkit) before 0.113 might allow local users to gain privileges via duplicate action IDs in action descriptions.(CVE-2015-3255)



Integer overflow in the authentication_agent_new_cookie function in PolicyKit (aka polkit) before 0.113 allows local users to gain privileges by creating a large number of connections, which triggers the issuance of a duplicate cookie value.(CVE-2015-4625)" );
	script_tag( name: "affected", value: "'polkit' package(s) on Huawei EulerOS V2.0SP3." );
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
if(release == "EULEROS-2.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "polkit", rpm: "polkit~0.112~12.h11", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit-devel", rpm: "polkit-devel~0.112~12.h11", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit-docs", rpm: "polkit-docs~0.112~12.h11", rls: "EULEROS-2.0SP3" ) )){
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

