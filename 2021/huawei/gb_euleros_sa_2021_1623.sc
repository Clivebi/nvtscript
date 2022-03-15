if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1623" );
	script_cve_id( "CVE-2019-20907", "CVE-2020-14422", "CVE-2020-26116", "CVE-2020-27619" );
	script_tag( name: "creation_date", value: "2021-03-12 07:23:55 +0000 (Fri, 12 Mar 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for python3 (EulerOS-SA-2021-1623)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.9\\.1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1623" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1623" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'python3' package(s) announced via the EulerOS-SA-2021-1623 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In Python 3 through 3.9.0, the Lib/test/multibytecodec_support.py CJK codec tests call eval() on content retrieved via HTTP.(CVE-2020-27619)

http.client in Python 3.x before 3.5.10, 3.6.x before 3.6.12, 3.7.x before 3.7.9, and 3.8.x before 3.8.5 allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR and LF control characters in the first argument of HTTPConnection.request.(CVE-2020-26116)

Lib/ipaddress.py in Python through 3.8.3 improperly computes hash values in the IPv4Interface and IPv6Interface classes, which might allow a remote attacker to cause a denial of service if an application is affected by the performance of a dictionary containing IPv4Interface or IPv6Interface objects, and this attacker can cause many dictionary entries to be created.(CVE-2020-14422)

In Lib/tarfile.py in Python through 3.8.3, an attacker is able to craft a TAR archive leading to an infinite loop when opened by tarfile.open, because _proc_pax lacks header validation.(CVE-2019-20907)" );
	script_tag( name: "affected", value: "'python3' package(s) on Huawei EulerOS Virtualization release 2.9.1." );
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
if(release == "EULEROSVIRT-2.9.1"){
	if(!isnull( res = isrpmvuln( pkg: "python3", rpm: "python3~3.7.4~7.h16.eulerosv2r9", rls: "EULEROSVIRT-2.9.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-unversioned-command", rpm: "python3-unversioned-command~3.7.4~7.h16.eulerosv2r9", rls: "EULEROSVIRT-2.9.1" ) )){
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

