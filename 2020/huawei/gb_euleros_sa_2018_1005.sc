if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1005" );
	script_cve_id( "CVE-2017-16879" );
	script_tag( name: "creation_date", value: "2020-01-23 11:08:04 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for ncurses (EulerOS-SA-2018-1005)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1005" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1005" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ncurses' package(s) announced via the EulerOS-SA-2018-1005 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Stack-based buffer overflow in the _nc_write_entry function in tinfo/write_entry.c in ncurses 6.0 allows attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted terminfo file, as demonstrated by tic.(CVE-2017-16879)" );
	script_tag( name: "affected", value: "'ncurses' package(s) on Huawei EulerOS V2.0SP1." );
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
if(release == "EULEROS-2.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "ncurses", rpm: "ncurses~5.9~13.20130511.h1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-base", rpm: "ncurses-base~5.9~13.20130511.h1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel", rpm: "ncurses-devel~5.9~13.20130511.h1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-libs", rpm: "ncurses-libs~5.9~13.20130511.h1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-term", rpm: "ncurses-term~5.9~13.20130511.h1", rls: "EULEROS-2.0SP1" ) )){
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

