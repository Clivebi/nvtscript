if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1294" );
	script_cve_id( "CVE-2019-16680", "CVE-2020-11736" );
	script_tag( name: "creation_date", value: "2021-02-22 08:15:19 +0000 (Mon, 22 Feb 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-20 17:23:00 +0000 (Fri, 20 Dec 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for file-roller (EulerOS-SA-2021-1294)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1294" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1294" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'file-roller' package(s) announced via the EulerOS-SA-2021-1294 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in GNOME file-roller before 3.29.91. It allows a single ./../ path traversal via a filename contained in a TAR archive, possibly overwriting a file during extraction.(CVE-2019-16680)

fr-archive-libarchive.c in GNOME file-roller through 3.36.1 allows Directory Traversal during extraction because it lacks a check of whether a file's parent is a symlink to a directory outside of the intended extraction location.(CVE-2020-11736)" );
	script_tag( name: "affected", value: "'file-roller' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "file-roller", rpm: "file-roller~3.14.2~7.h4", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-roller-nautilus", rpm: "file-roller-nautilus~3.14.2~7.h4", rls: "EULEROS-2.0SP2" ) )){
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

