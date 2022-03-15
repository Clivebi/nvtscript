if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1002" );
	script_cve_id( "CVE-2019-14866" );
	script_tag( name: "creation_date", value: "2020-01-23 13:15:14 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-10 14:27:00 +0000 (Fri, 10 Jan 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for cpio (EulerOS-SA-2020-1002)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1002" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1002" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'cpio' package(s) announced via the EulerOS-SA-2020-1002 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "cpio does not properly validate the values written in the header of a TAR file through the to_oct() function. When creating a TAR file from a list of files and one of those is another TAR file with a big size, cpio will generate the resulting file with the content extracted from the input one. This leads to unexpected results as the newly generated TAR file could have files with permissions the owner of the input TAR file did not have or in paths he did not have access to.(CVE-2019-14866)" );
	script_tag( name: "affected", value: "'cpio' package(s) on Huawei EulerOS V2.0SP8." );
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
if(release == "EULEROS-2.0SP8"){
	if(!isnull( res = isrpmvuln( pkg: "cpio", rpm: "cpio~2.12~9.h2.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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

