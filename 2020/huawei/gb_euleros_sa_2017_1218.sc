if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2017.1218" );
	script_cve_id( "CVE-2017-1000115", "CVE-2017-1000116" );
	script_tag( name: "creation_date", value: "2020-01-23 10:59:40 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for mercurial (EulerOS-SA-2017-1218)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2017-1218" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1218" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'mercurial' package(s) announced via the EulerOS-SA-2017-1218 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was found in the way Mercurial handles path auditing and caches the results. An attacker could abuse a repository with a series of commits mixing symlinks and regular files/directories to trick Mercurial into writing outside of a given repository. (CVE-2017-1000115)

A shell command injection flaw related to the handling of 'ssh' URLs has been discovered in Mercurial. This can be exploited to execute shell commands with the privileges of the user running the Mercurial client, for example, when performing a 'checkout' or 'update' action on a sub-repository within a malicious repository or a legitimate repository containing a malicious commit. (CVE-2017-1000116)" );
	script_tag( name: "affected", value: "'mercurial' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "mercurial", rpm: "mercurial~2.6.2~8", rls: "EULEROS-2.0SP2" ) )){
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

