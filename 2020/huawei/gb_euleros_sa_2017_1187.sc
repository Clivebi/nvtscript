if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2017.1187" );
	script_cve_id( "CVE-2014-9938", "CVE-2017-1000117", "CVE-2017-8386" );
	script_tag( name: "creation_date", value: "2020-01-23 10:57:11 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-29 20:26:00 +0000 (Wed, 29 Apr 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for git (EulerOS-SA-2017-1187)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2017-1187" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1187" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'git' package(s) announced via the EulerOS-SA-2017-1187 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was found that the git-prompt.sh script shipped with git failed to correctly handle branch names containing special characters. A specially crafted git repository could use this flaw to execute arbitrary commands if a user working with the repository configured their shell to include repository information in the prompt. (CVE-2014-9938)

A flaw was found in the way git-shell handled command-line options for the restricted set of git-shell commands. A remote, authenticated attacker could use this flaw to bypass git-shell restrictions, to view and manipulate files, by abusing the instance of the less command launched using crafted command-line options. (CVE-2017-8386)

A shell command injection flaw related to the handling of ''ssh'' URLs has been discovered in Git. An attacker could use this flaw to execute shell commands with the privileges of the user running the Git client, for example, when performing a ''clone'' action on a malicious repository or a legitimate repository containing a malicious commit. (CVE-2017-1000117)" );
	script_tag( name: "affected", value: "'git' package(s) on Huawei EulerOS V2.0SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "git", rpm: "git~1.8.3.1~12", rls: "EULEROS-2.0SP1" ) )){
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

