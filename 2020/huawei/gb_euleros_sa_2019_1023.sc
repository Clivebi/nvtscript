if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1023" );
	script_cve_id( "CVE-2018-16540", "CVE-2018-16543", "CVE-2018-16863" );
	script_tag( name: "creation_date", value: "2020-01-23 11:28:01 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-25 14:28:00 +0000 (Thu, 25 Apr 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for ghostscript (EulerOS-SA-2019-1023)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1023" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1023" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ghostscript' package(s) announced via the EulerOS-SA-2019-1023 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ghostscript: gssetresolution and gsgetresolution memory corruption(CVE-2018-16543)

ghostscript: use-after-free in copydevice handling(CVE-2018-16540)

ghostscript: incomplete fix for CVE-2018-16509 (CVE-2018-16863)" );
	script_tag( name: "affected", value: "'ghostscript' package(s) on Huawei EulerOS V2.0SP5." );
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
if(release == "EULEROS-2.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "ghostscript", rpm: "ghostscript~9.07~31.6.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-cups", rpm: "ghostscript-cups~9.07~31.6.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

