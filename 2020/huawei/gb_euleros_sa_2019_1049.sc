if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1049" );
	script_cve_id( "CVE-2018-15911", "CVE-2018-16539", "CVE-2018-16802", "CVE-2018-16863", "CVE-2018-17183", "CVE-2018-17961", "CVE-2018-18073", "CVE-2018-18284", "CVE-2018-19134", "CVE-2018-19409" );
	script_tag( name: "creation_date", value: "2020-01-23 11:28:57 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for ghostscript (EulerOS-SA-2019-1049)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1049" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1049" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ghostscript' package(s) announced via the EulerOS-SA-2019-1049 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ghostscript: Incorrect 'restoration of privilege' checking when running out of stack during exception handling (CVE-2018-16802)

ghostscript: User-writable error exception table (CVE-2018-17183)

ghostscript: Saved execution stacks can leak operator arrays (incomplete fix for CVE-2018-17183) (CVE-2018-17961)

ghostscript: Saved execution stacks can leak operator arrays (CVE-2018-18073)

ghostscript: 1Policy operator allows a sandbox protection bypass (CVE-2018-18284)

ghostscript: Type confusion in setpattern (700141) (CVE-2018-19134)

ghostscript: Improperly implemented security check in zsetdevice function in psi/zdevice.c (CVE-2018-19409)

ghostscript: Uninitialized memory access in the aesdecode operator (699665) (CVE-2018-15911)

ghostscript: incomplete fix for CVE-2018-16509 (CVE-2018-16863)

ghostscript: incorrect access checking in temp file handling to disclose contents of files (699658) (CVE-2018-16539)" );
	script_tag( name: "affected", value: "'ghostscript' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "ghostscript", rpm: "ghostscript~9.07~31.6.h3", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-cups", rpm: "ghostscript-cups~9.07~31.6.h3", rls: "EULEROS-2.0SP2" ) )){
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

