if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.2260" );
	script_cve_id( "CVE-2020-10737" );
	script_tag( name: "creation_date", value: "2020-10-30 10:45:08 +0000 (Fri, 30 Oct 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "3.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-02 16:08:00 +0000 (Tue, 02 Jun 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for oddjob (EulerOS-SA-2020-2260)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-2260" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2260" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'oddjob' package(s) announced via the EulerOS-SA-2020-2260 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A race condition was found in the mkhomedir tool shipped with the oddjob package in versions before 0.34.5 and 0.34.6 wherein, during the home creation, mkhomedir copies the /etc/skel directory into the newly created home and changes its ownership to the home's user without properly checking the homedir path. This flaw allows an attacker to leverage this issue by creating a symlink point to a target folder, which then has its ownership transferred to the new home directory's unprivileged user.(CVE-2020-10737)" );
	script_tag( name: "affected", value: "'oddjob' package(s) on Huawei EulerOS V2.0SP5." );
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
if(release == "EULEROS-2.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "oddjob", rpm: "oddjob~0.31.5~4.h1.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "oddjob-mkhomedir", rpm: "oddjob-mkhomedir~0.31.5~4.h1.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

