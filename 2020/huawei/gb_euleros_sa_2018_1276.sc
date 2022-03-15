if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1276" );
	script_cve_id( "CVE-2018-10754" );
	script_tag( name: "creation_date", value: "2020-01-23 11:19:52 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-05-27 07:14:38 +0000 (Thu, 27 May 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for ncurses (EulerOS-SA-2018-1276)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1276" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1276" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ncurses' package(s) announced via the EulerOS-SA-2018-1276 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A NULL pointer dereference was found in the way the _nc_parse_entry function parses terminfo data for compilation. An attacker able to provide specially crafted terminfo data could use this flaw to crash the application parsing it.(CVE-2018-10754)" );
	script_tag( name: "affected", value: "'ncurses' package(s) on Huawei EulerOS Virtualization 2.5.2." );
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
if(release == "EULEROSVIRT-2.5.2"){
	if(!isnull( res = isrpmvuln( pkg: "ncurses", rpm: "ncurses~5.9~13.20130511.h3", rls: "EULEROSVIRT-2.5.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-base", rpm: "ncurses-base~5.9~13.20130511.h3", rls: "EULEROSVIRT-2.5.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-libs", rpm: "ncurses-libs~5.9~13.20130511.h3", rls: "EULEROSVIRT-2.5.2" ) )){
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

