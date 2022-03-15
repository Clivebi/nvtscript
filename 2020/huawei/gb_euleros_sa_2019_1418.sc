if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1418" );
	script_cve_id( "CVE-2014-6271", "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187", "CVE-2016-7543", "CVE-2016-9401" );
	script_tag( name: "creation_date", value: "2020-01-23 11:43:28 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-01 21:38:00 +0000 (Mon, 01 Feb 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for bash (EulerOS-SA-2019-1418)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.1\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1418" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1418" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'bash' package(s) announced via the EulerOS-SA-2019-1418 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was found that the fix for CVE-2014-6271 was incomplete, and Bash still allowed certain characters to be injected into other environments via specially crafted environment variables. An attacker could potentially use this flaw to override or bypass environment restrictions to execute shell commands. Certain services and applications allow remote unauthenticated attackers to provide environment variables, allowing them to exploit this issue.(CVE-2014-7169)

A denial of service flaw was found in the way bash handled popd commands. A poorly written shell script could cause bash to crash resulting in a local denial of service limited to a specific bash session.(CVE-2016-9401)

It was discovered that the fixed-sized redir_stack could be forced to overflow in the Bash parser, resulting in memory corruption, and possibly leading to arbitrary code execution when evaluating untrusted input that would not otherwise be run as code.(CVE-2014-7186)

An off-by-one error was discovered in the way Bash was handling deeply nested flow control constructs. Depending on the layout of the .bss segment, this could allow arbitrary execution of code that would not otherwise be executed by Bash.(CVE-2014-7187)

A flaw was found in the way Bash evaluated certain specially crafted environment variables. An attacker could use this flaw to override or bypass environment restrictions to execute shell commands. Certain services and applications allow remote unauthenticated attackers to provide environment variables, allowing them to exploit this issue.(CVE-2014-6271)

An arbitrary command injection flaw was found in the way bash processed the SHELLOPTS and PS4 environment variables. A local, authenticated attacker could use this flaw to exploit poorly written setuid programs to elevate their privileges under certain circumstances.(CVE-2016-7543)" );
	script_tag( name: "affected", value: "'bash' package(s) on Huawei EulerOS Virtualization 3.0.1.0." );
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
if(release == "EULEROSVIRT-3.0.1.0"){
	if(!isnull( res = isrpmvuln( pkg: "bash", rpm: "bash~4.2.46~30.h3.eulerosv2r7", rls: "EULEROSVIRT-3.0.1.0" ) )){
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

