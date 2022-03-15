if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1215" );
	script_cve_id( "CVE-2018-10194", "CVE-2018-15910", "CVE-2018-16509", "CVE-2018-16542" );
	script_tag( name: "creation_date", value: "2020-01-23 11:35:01 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-24 16:21:00 +0000 (Wed, 24 Jul 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for ghostscript (EulerOS-SA-2019-1215)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.4" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1215" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1215" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ghostscript' package(s) announced via the EulerOS-SA-2019-1215 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The set_text_distance function in devices/vector/gdevpdts.c in the pdfwrite component in Artifex Ghostscript through 9.22 does not prevent overflows in text-positioning calculation, which allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted PDF document.(CVE-2018-10194)

It was discovered that the type of the LockDistillerParams parameter is not properly verified. An attacker could possibly exploit this to bypass the -dSAFER protection and crash ghostscript or, possibly, execute arbitrary code in the ghostscript context via a specially crafted PostScript document.(CVE-2018-15910)

It was discovered that the ghostscript /invalidaccess checks fail under certain conditions. An attacker could possibly exploit this to bypass the -dSAFER protection and, for example, execute arbitrary shell commands via a specially crafted PostScript document.(CVE-2018-16509)

It was discovered that ghostscript did not properly handle certain stack overflow error conditions. An attacker could possibly exploit this to bypass the -dSAFER protection and crash ghostscript or, possibly, execute arbitrary code in the ghostscript context via a specially crafted PostScript document.(CVE-2018-16542)" );
	script_tag( name: "affected", value: "'ghostscript' package(s) on Huawei EulerOS Virtualization 2.5.4." );
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
if(release == "EULEROSVIRT-2.5.4"){
	if(!isnull( res = isrpmvuln( pkg: "ghostscript", rpm: "ghostscript~9.07~29.2.h1", rls: "EULEROSVIRT-2.5.4" ) )){
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

