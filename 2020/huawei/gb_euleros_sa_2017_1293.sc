if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2017.1293" );
	script_cve_id( "CVE-2014-9474" );
	script_tag( name: "creation_date", value: "2020-01-23 11:06:19 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-05 23:16:00 +0000 (Sun, 05 Nov 2017)" );
	script_name( "Huawei EulerOS: Security Advisory for mpfr (EulerOS-SA-2017-1293)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2017-1293" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1293" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'mpfr' package(s) announced via the EulerOS-SA-2017-1293 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Buffer overflow in the mpfr_strtofr function in GNU MPFR before 3.1.2-p11 allows context-dependent attackers to have unspecified impact via vectors related to incorrect documentation for mpn_set_str.(CVE-2014-9474)" );
	script_tag( name: "affected", value: "'mpfr' package(s) on Huawei EulerOS V2.0SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "mpfr", rpm: "mpfr~3.1.1~4.h1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mpfr-devel", rpm: "mpfr-devel~3.1.1~4.h1", rls: "EULEROS-2.0SP1" ) )){
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

