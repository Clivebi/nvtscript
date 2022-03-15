if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2017.1163" );
	script_cve_id( "CVE-2016-0634", "CVE-2016-9401" );
	script_tag( name: "creation_date", value: "2020-01-23 10:54:29 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for bash (EulerOS-SA-2017-1163)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2017-1163" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1163" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'bash' package(s) announced via the EulerOS-SA-2017-1163 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An arbitrary command injection flaw was found in the way bash processed the hostname value. A malicious DHCP server could use this flaw to execute arbitrary commands on the DHCP client machines running bash under specific circumstances. (CVE-2016-0634)

An arbitrary command injection flaw was found in the way bash processed the SHELLOPTS and PS4 environment variables. A local, authenticated attacker could use this flaw to exploit poorly written setuid programs to elevate their privileges under certain circumstances. (CVE-2016-7543)

A denial of service flaw was found in the way bash handled popd commands. A poorly written shell script could cause bash to crash resulting in a local denial of service limited to a specific bash session. (CVE-2016-9401)" );
	script_tag( name: "affected", value: "'bash' package(s) on Huawei EulerOS V2.0SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "bash", rpm: "bash~4.2.46~28", rls: "EULEROS-2.0SP1" ) )){
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

