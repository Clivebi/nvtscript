if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1049" );
	script_cve_id( "CVE-2020-14344", "CVE-2020-14363" );
	script_tag( name: "creation_date", value: "2021-01-08 21:54:53 +0000 (Fri, 08 Jan 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 18:15:00 +0000 (Wed, 30 Sep 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for libX11 (EulerOS-SA-2021-1049)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.2\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1049" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1049" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libX11' package(s) announced via the EulerOS-SA-2021-1049 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An integer overflow vulnerability leading to a double-free was found in libX11. This flaw allows a local privileged attacker to cause an application compiled with libX11 to crash, or in some cases, result in arbitrary code execution. The highest threat from this flaw is to confidentiality, integrity as well as system availability.(CVE-2020-14363)

An integer overflow leading to a heap-buffer overflow was found in The X Input Method (XIM) client was implemented in libX11 before version 1.6.10. As per upstream this is security relevant when setuid programs call XIM client functions while running with elevated privileges. No such programs are shipped with Red Hat Enterprise Linux.(CVE-2020-14344)" );
	script_tag( name: "affected", value: "'libX11' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0." );
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
if(release == "EULEROSVIRTARM64-3.0.2.0"){
	if(!isnull( res = isrpmvuln( pkg: "libX11", rpm: "libX11~1.6.5~1.h5", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-common", rpm: "libX11-common~1.6.5~1.h5", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
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

