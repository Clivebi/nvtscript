if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1417" );
	script_cve_id( "CVE-2020-25692" );
	script_tag( name: "creation_date", value: "2021-03-05 07:05:40 +0000 (Fri, 05 Mar 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-08 12:15:00 +0000 (Fri, 08 Jan 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for openldap (EulerOS-SA-2021-1417)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.2\\.6" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1417" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1417" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'openldap' package(s) announced via the EulerOS-SA-2021-1417 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A NULL pointer dereference was found in OpenLDAP server and was fixed in openldap 2.4.55, during a request for renaming RDNs. An unauthenticated attacker could remotely crash the slapd process by sending a specially crafted request, causing a Denial of Service.(CVE-2020-16592)" );
	script_tag( name: "affected", value: "'openldap' package(s) on Huawei EulerOS Virtualization 3.0.2.6." );
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
if(release == "EULEROSVIRT-3.0.2.6"){
	if(!isnull( res = isrpmvuln( pkg: "openldap", rpm: "openldap~2.4.44~15.h11.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap-clients", rpm: "openldap-clients~2.4.44~15.h11.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.6" ) )){
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

