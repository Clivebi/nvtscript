if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2016.1069" );
	script_cve_id( "CVE-2016-4455" );
	script_tag( name: "creation_date", value: "2020-01-23 10:42:09 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-02 19:10:00 +0000 (Wed, 02 Sep 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for subscription-manager, python-rhsm (EulerOS-SA-2016-1069)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2016-1069" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1069" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'subscription-manager, python-rhsm' package(s) announced via the EulerOS-SA-2016-1069 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was found that subscription-manager set weak permissions on files in /var/lib/rhsm/, causing an information disclosure. A local, unprivileged user could use this flaw to access sensitive data that could potentially be used in a social engineering attack.(CVE-2016-4455)" );
	script_tag( name: "affected", value: "'subscription-manager, python-rhsm' package(s) on Huawei EulerOS V2.0SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "subscription-manager", rpm: "subscription-manager~1.17.15~1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subscription-manager-gui", rpm: "subscription-manager-gui~1.17.15~1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rhsm", rpm: "python-rhsm~1.17.9~1", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rhsm-certificates", rpm: "python-rhsm-certificates~1.17.9~1", rls: "EULEROS-2.0SP1" ) )){
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

