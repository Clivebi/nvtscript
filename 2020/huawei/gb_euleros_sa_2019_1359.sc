if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1359" );
	script_cve_id( "CVE-2019-9948" );
	script_tag( name: "creation_date", value: "2020-01-23 11:40:21 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for python (EulerOS-SA-2019-1359)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1359" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1359" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'python' package(s) announced via the EulerOS-SA-2019-1359 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "urllib in Python 2.x through 2.7.16 supports the local_file: scheme, which makes it easier for remote attackers to bypass protection mechanisms that blacklist file: URIs, as demonstrated by triggering a urllib.urlopen('local_file:///etc/passwd') call.(CVE-2019-9948)" );
	script_tag( name: "affected", value: "'python' package(s) on Huawei EulerOS Virtualization 2.5.3." );
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
if(release == "EULEROSVIRT-2.5.3"){
	if(!isnull( res = isrpmvuln( pkg: "python", rpm: "python~2.7.5~58.h12", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-devel", rpm: "python-devel~2.7.5~58.h12", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libs", rpm: "python-libs~2.7.5~58.h12", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tools", rpm: "python-tools~2.7.5~58.h12", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tkinter", rpm: "tkinter~2.7.5~58.h12", rls: "EULEROSVIRT-2.5.3" ) )){
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
