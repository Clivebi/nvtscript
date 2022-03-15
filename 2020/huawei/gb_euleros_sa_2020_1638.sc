if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1638" );
	script_cve_id( "CVE-2012-6711" );
	script_tag( name: "creation_date", value: "2020-06-16 05:47:45 +0000 (Tue, 16 Jun 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-20 09:15:00 +0000 (Thu, 20 Jun 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for bash (EulerOS-SA-2020-1638)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1638" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1638" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'bash' package(s) announced via the EulerOS-SA-2020-1638 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A heap-based buffer overflow exists in GNU Bash before 4.3 when wide characters, not supported by the current locale set in the LC_CTYPE environment variable, are printed through the echo built-in function. A local attacker, who can provide data to print through the 'echo -e' built-in function, may use this flaw to crash a script or execute code with the privileges of the bash process. This occurs because ansicstr() in lib/sh/strtrans.c mishandles u32cconv().(CVE-2012-6711)" );
	script_tag( name: "affected", value: "'bash' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "bash", rpm: "bash~4.2.46~28.h6", rls: "EULEROS-2.0SP2" ) )){
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

