if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1080" );
	script_cve_id( "CVE-2018-10897" );
	script_tag( name: "creation_date", value: "2020-01-23 11:30:38 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-09-12T02:24:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-12 02:24:48 +0000 (Sun, 12 Sep 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-09 12:42:00 +0000 (Thu, 09 Sep 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for yum-utils (EulerOS-SA-2019-1080)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1080" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1080" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'yum-utils' package(s) announced via the EulerOS-SA-2019-1080 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A directory traversal issue was found in reposync, a part of yum-utils, where reposync fails to sanitize paths in remote repository configuration files. If an attacker controls a repository, they may be able to copy files outside of the destination directory on the targeted system via path traversal. If reposync is running with heightened privileges on a targeted system, this flaw could potentially result in system compromise via the overwriting of critical system files. Version 1.1.31 and older are believed to be affected.(CVE-2018-10897)" );
	script_tag( name: "affected", value: "'yum-utils' package(s) on Huawei EulerOS Virtualization 2.5.2." );
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
if(release == "EULEROSVIRT-2.5.2"){
	if(!isnull( res = isrpmvuln( pkg: "yum-utils", rpm: "yum-utils~1.1.31~42.h1", rls: "EULEROSVIRT-2.5.2" ) )){
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

