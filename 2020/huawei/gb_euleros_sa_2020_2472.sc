if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.2472" );
	script_cve_id( "CVE-2020-14422" );
	script_tag( name: "creation_date", value: "2020-11-05 08:49:49 +0000 (Thu, 05 Nov 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-03 15:33:00 +0000 (Wed, 03 Feb 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for python-ipaddress (EulerOS-SA-2020-2472)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.6\\.6" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-2472" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2472" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'python-ipaddress' package(s) announced via the EulerOS-SA-2020-2472 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Lib/ipaddress.py in Python through 3.8.3 improperly computes hash values in the IPv4Interface and IPv6Interface classes, which might allow a remote attacker to cause a denial of service if an application is affected by the performance of a dictionary containing IPv4Interface or IPv6Interface objects, and this attacker can cause many dictionary entries to be created.(CVE-2020-14422)" );
	script_tag( name: "affected", value: "'python-ipaddress' package(s) on Huawei EulerOS Virtualization 3.0.6.6." );
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
if(release == "EULEROSVIRT-3.0.6.6"){
	if(!isnull( res = isrpmvuln( pkg: "python-ipaddress", rpm: "python-ipaddress~1.0.16~2.eulerosv2r7.h1", rls: "EULEROSVIRT-3.0.6.6" ) )){
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

