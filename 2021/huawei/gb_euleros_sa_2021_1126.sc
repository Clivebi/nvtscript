if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1126" );
	script_cve_id( "CVE-2018-17407" );
	script_tag( name: "creation_date", value: "2021-01-19 10:12:26 +0000 (Tue, 19 Jan 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-15 16:11:00 +0000 (Thu, 15 Nov 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for texlive (EulerOS-SA-2021-1126)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1126" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1126" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'texlive' package(s) announced via the EulerOS-SA-2021-1126 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in t1_check_unusual_charstring functions in writet1.c files in TeX Live before 2018-09-21. A buffer overflow in the handling of Type 1 fonts allows arbitrary code execution when a malicious font is loaded by one of the vulnerable tools: pdflatex, pdftex, dvips, or luatex.(CVE-2018-17407)" );
	script_tag( name: "affected", value: "'texlive' package(s) on Huawei EulerOS V2.0SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "texlive", rpm: "texlive~2012~38.20130427_r30134.h3", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "texlive-base", rpm: "texlive-base~2012~38.20130427_r30134.h3", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "texlive-kpathsea-lib", rpm: "texlive-kpathsea-lib~2012~38.20130427_r30134.h3", rls: "EULEROS-2.0SP3" ) )){
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

