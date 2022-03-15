if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1226" );
	script_cve_id( "CVE-2018-10768" );
	script_tag( name: "creation_date", value: "2020-01-23 11:18:03 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-25 18:38:00 +0000 (Thu, 25 Apr 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for poppler (EulerOS-SA-2018-1226)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1226" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1226" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'poppler' package(s) announced via the EulerOS-SA-2018-1226 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "There is a NULL pointer dereference in the AnnotPath::getCoordsLength function in Annot.h in an Ubuntu package for Poppler 0.24.5. A crafted input will lead to a remote denial of service attack. Later Ubuntu packages such as for Poppler 0.41.0 are not affected.(CVE-2018-10768)" );
	script_tag( name: "affected", value: "'poppler' package(s) on Huawei EulerOS V2.0SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "poppler", rpm: "poppler~0.26.5~17.h11", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "poppler-glib", rpm: "poppler-glib~0.26.5~17.h11", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "poppler-qt", rpm: "poppler-qt~0.26.5~17.h11", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "poppler-utils", rpm: "poppler-utils~0.26.5~17.h11", rls: "EULEROS-2.0SP3" ) )){
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

