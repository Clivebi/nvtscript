if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2634" );
	script_cve_id( "CVE-2017-13728", "CVE-2017-13729", "CVE-2017-13730", "CVE-2017-13731", "CVE-2017-13732", "CVE-2017-13733", "CVE-2017-13734", "CVE-2018-19211", "CVE-2019-17594", "CVE-2019-17595" );
	script_tag( name: "creation_date", value: "2020-01-23 13:10:23 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for ncurses (EulerOS-SA-2019-2634)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2634" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2634" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ncurses' package(s) announced via the EulerOS-SA-2019-2634 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In ncurses 6.1, there is a NULL pointer dereference at function _nc_parse_entry in parse_entry.c that will lead to a denial of service attack. The product proceeds to the dereference code path even after a 'dubious character `*' in name or alias field' detection.(CVE-2018-19211)

There is a heap-based buffer over-read in the _nc_find_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.(CVE-2019-17594)

There is a heap-based buffer over-read in the fmt_entry function in tinfo/comp_hash.c in the terminfo library in ncurses before 6.1-20191012.(CVE-2019-17595)

There is an illegal address access in the _nc_safe_strcat function in strings.c in ncurses 6.0 that will lead to a remote denial of service attack.(CVE-2017-13734)

There is an illegal address access in the _nc_save_str function in alloc_entry.c in ncurses 6.0. It will lead to a remote denial of service attack.(CVE-2017-13729)

There is an illegal address access in the fmt_entry function in progs/dump_entry.c in ncurses 6.0 that might lead to a remote denial of service attack.(CVE-2017-13733)

There is an illegal address access in the function _nc_read_entry_source() in progs/tic.c in ncurses 6.0 that might lead to a remote denial of service attack.(CVE-2017-13730)

There is an illegal address access in the function dump_uses() in progs/dump_entry.c in ncurses 6.0 that might lead to a remote denial of service attack.(CVE-2017-13732)

There is an illegal address access in the function postprocess_termcap() in parse_entry.c in ncurses 6.0 that will lead to a remote denial of service attack.(CVE-2017-13731)

There is an infinite loop in the next_char function in comp_scan.c in ncurses 6.0, related to libtic. A crafted input will lead to a remote denial of service attack.(CVE-2017-13728)" );
	script_tag( name: "affected", value: "'ncurses' package(s) on Huawei EulerOS V2.0SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "ncurses", rpm: "ncurses~5.9~13.20130511.h5", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-base", rpm: "ncurses-base~5.9~13.20130511.h5", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-devel", rpm: "ncurses-devel~5.9~13.20130511.h5", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-libs", rpm: "ncurses-libs~5.9~13.20130511.h5", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ncurses-term", rpm: "ncurses-term~5.9~13.20130511.h5", rls: "EULEROS-2.0SP3" ) )){
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

