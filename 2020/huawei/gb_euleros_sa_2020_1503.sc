if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1503" );
	script_cve_id( "CVE-2020-5260" );
	script_tag( name: "creation_date", value: "2020-04-20 08:04:45 +0000 (Mon, 20 Apr 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-19 18:21:00 +0000 (Fri, 19 Mar 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for git (EulerOS-SA-2020-1503)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1503" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1503" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'git' package(s) announced via the EulerOS-SA-2020-1503 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Affected versions of Git have a vulnerability whereby Git can be tricked into sending private credentials to a host controlled by an attacker. Git uses external 'credential helper' programs to store and retrieve passwords or other credentials from secure storage provided by the operating system. Specially-crafted URLs that contain an encoded newline can inject unintended values into the credential helper protocol stream, causing the credential helper to retrieve the password for one server (e.g., good.example.com) for an HTTP request being made to another server (e.g., evil.example.com), resulting in credentials for the former being sent to the latter. There are no restrictions on the relationship between the two, meaning that an attacker can craft a URL that will present stored credentials for any host to a host of their choosing. The vulnerability can be triggered by feeding a malicious URL to git clone. However, the affected URLs look rather suspicious, the likely vector would be through systems which automatically clone URLs not visible to the user, such as Git submodules, or package systems built around Git. The problem has been patched in the versions published on April 14th, 2020, going back to v2.17.x. Anyone wishing to backport the change further can do so by applying commit 9a6bbee (the full release includes extra checks for git fsck, but that commit is sufficient to protect clients against the vulnerability). The patched versions are: 2.17.4, 2.18.3, 2.19.4, 2.20.3, 2.21.2, 2.22.3, 2.23.2, 2.24.2, 2.25.3, 2.26.1.(CVE-2020-5260)" );
	script_tag( name: "affected", value: "'git' package(s) on Huawei EulerOS V2.0SP8." );
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
	if(!isnull( res = isrpmvuln( pkg: "git", rpm: "git~2.19.1~1.h6.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-core", rpm: "git-core~2.19.1~1.h6.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-core-doc", rpm: "git-core-doc~2.19.1~1.h6.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Git", rpm: "perl-Git~2.19.1~1.h6.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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

