if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1562" );
	script_cve_id( "CVE-2019-19923", "CVE-2019-19924", "CVE-2019-19926", "CVE-2019-20218" );
	script_tag( name: "creation_date", value: "2020-04-30 12:13:44 +0000 (Thu, 30 Apr 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-14 11:15:00 +0000 (Tue, 14 Jan 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for sqlite (EulerOS-SA-2020-1562)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.2\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1562" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1562" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'sqlite' package(s) announced via the EulerOS-SA-2020-1562 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "multiSelect in select.c in SQLite 3.30.1 mishandles certain errors during parsing, as demonstrated by errors from sqlite3WindowRewrite() calls. NOTE: this vulnerability exists because of an incomplete fix for CVE-2019-19880.(CVE-2019-19924)

SQLite 3.30.1 mishandles certain parser-tree rewriting, related to expr.c, vdbeaux.c, and window.c. This is caused by incorrect sqlite3WindowRewrite() error handling.(CVE-2019-19923)

multiSelect in select.c in SQLite 3.30.1 mishandles certain errors during parsing, as demonstrated by errors from sqlite3WindowRewrite() calls. NOTE: this vulnerability exists because of an incomplete fix for CVE-2019-19880.(CVE-2019-19926)

The XSLoader::load method in XSLoader in Perl does not properly locate .so files when called in a string eval, which might allow local users to execute arbitrary code via a Trojan horse library under the current working directory.(CVE-2019-20218)" );
	script_tag( name: "affected", value: "'sqlite' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "sqlite", rpm: "sqlite~3.7.17~8.h9", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
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

