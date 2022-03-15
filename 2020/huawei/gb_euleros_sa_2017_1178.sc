if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2017.1178" );
	script_cve_id( "CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679", "CVE-2017-9788" );
	script_tag( name: "creation_date", value: "2020-01-23 10:55:41 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for httpd (EulerOS-SA-2017-1178)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2017-1178" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1178" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'httpd' package(s) announced via the EulerOS-SA-2017-1178 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the httpd's mod_auth_digest module did not properly initialize memory before using it when processing certain headers related to digest authentication. A remote attacker could possibly use this flaw to disclose potentially sensitive information or cause httpd child process to crash by sending specially crafted requests to a server. (CVE-2017-9788)

It was discovered that the use of httpd's ap_get_basic_auth_pw() API function outside of the authentication phase could lead to authentication bypass. A remote attacker could possibly use this flaw to bypass required authentication if the API was used incorrectly by one of the modules used by httpd. (CVE-2017-3167)

A NULL pointer dereference flaw was found in the httpd's mod_ssl module. A remote attacker could use this flaw to cause an httpd child process to crash if another module used by httpd called a certain API function during the processing of an HTTPS request. (CVE-2017-3169)

A buffer over-read flaw was found in the httpd's ap_find_token() function. A remote attacker could use this flaw to cause httpd child process to crash via a specially crafted HTTP request. (CVE-2017-7668)

A buffer over-read flaw was found in the httpd's mod_mime module. A user permitted to modify httpd's MIME configuration could use this flaw to cause httpd child process to crash. (CVE-2017-7679)" );
	script_tag( name: "affected", value: "'httpd' package(s) on Huawei EulerOS V2.0SP2." );
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
if(release == "EULEROS-2.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "httpd", rpm: "httpd~2.4.6~45.0.1.4.h4", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "httpd-devel", rpm: "httpd-devel~2.4.6~45.0.1.4.h4", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "httpd-manual", rpm: "httpd-manual~2.4.6~45.0.1.4.h4", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "httpd-tools", rpm: "httpd-tools~2.4.6~45.0.1.4.h4", rls: "EULEROS-2.0SP2" ) )){
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

